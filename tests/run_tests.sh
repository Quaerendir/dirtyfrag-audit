#!/bin/bash
# Regression tests for audit_dirtyfrag.sh.
#
# Each case builds a fixture filesystem tree (os-release, modules.builtin,
# kernel modules, modprobe.d) and runs the script against it
# with the mock commands in tests/mock_bin, then asserts the exit code and
# the verdict banner. Exit codes: 0 SAFE, 1 VULNERABLE, 2 MITIGATED.

set -u

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SCRIPT="${HERE}/../audit_dirtyfrag.sh"
MOCK_BIN="${HERE}/mock_bin"

# The script ignores its test hooks for root, so a root run would audit the
# real host instead of the fixtures.
if [[ $EUID -eq 0 ]]; then
    echo "ERROR: run the tests as a non-root user" >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
LAST_OUT=""

# new_root <kernel-release> <os-id> <version-id>: create a fixture tree for
# a host with nothing built in, loaded or blacklisted; print its path.
# Runs in a $( ) subshell, so it cannot keep a counter: mktemp gives every
# case its own tree.
new_root() {
    local r
    r=$(mktemp -d "${TMP}/root.XXXXXX")
    mkdir -p "$r/etc/modprobe.d" "$r/lib/modules/$1" "$r/proc/1" "$r/boot"
    : > "$r/lib/modules/$1/modules.builtin"
    : > "$r/proc/cmdline"
    : > "$r/proc/1/environ"
    printf 'NAME="%s"\nID=%s\nVERSION_ID="%s"\n' "$2" "$2" "$3" > "$r/etc/os-release"
    echo "$1" > "$r/.krel"
    echo "$r"
}

# check <name> <root> <exit-code> <verdict> [VAR=value ...]
check() {
    local name=$1 root=$2 want_rc=$3 want_verdict=$4
    shift 4
    local krel out rc verdict ok=1
    krel=$(cat "$root/.krel")
    out=$(env -i HOME="$TMP" PATH=/usr/bin:/bin \
        DIRTYFRAG_TEST_PATH="$MOCK_BIN" DIRTYFRAG_TEST_ROOT="$root" \
        MOCK_UNAME_R="$krel" "$@" bash "$SCRIPT" 2>&1)
    rc=$?
    out=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$out")
    LAST_OUT=$out
    verdict=$(grep -oE '(SAFE|MITIGATED|VULNERABLE|UNKNOWN) — ' <<< "$out" | head -1 | cut -d' ' -f1)

    # Guard: a script that bypasses the mocks would report the real kernel.
    if ! grep -q "Kernel     : ${krel}\$" <<< "$out"; then
        echo "  FAIL: $name — mock kernel ${krel} not used"
        ok=0
    fi
    if grep -qE 'syntax error|unbound variable|command not found' <<< "$out"; then
        echo "  FAIL: $name — shell error in output:"
        grep -E 'syntax error|unbound variable|command not found' <<< "$out" | sed 's/^/        /'
        ok=0
    fi
    if [[ "$rc" != "$want_rc" || "$verdict" != "$want_verdict" ]]; then
        echo "  FAIL: $name — expected ${want_verdict}/${want_rc}, got ${verdict:-none}/${rc}"
        ok=0
    fi
    if (( ok )); then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
}

MOCK_KCARE="${HERE}/mock_kcare"

# add_ko <root> <module path>: mark a module as shipped for the kernel.
add_ko() {
    local k
    k=$(cat "$1/.krel")
    mkdir -p "$(dirname "$1/lib/modules/$k/$2")"
    : > "$1/lib/modules/$k/$2"
}

# ship_esp <root>: ship esp4/esp6 as loadable modules, as almost every
# distro kernel does (zstd-compressed, like current Ubuntu).
ship_esp() {
    add_ko "$1" kernel/net/ipv4/esp4.ko.zst
    add_ko "$1" kernel/net/ipv6/esp6.ko.zst
}

# builtin <root> <module path>: mark a module as built into the kernel.
builtin() {
    echo "$2" >> "$1/lib/modules/$(cat "$1/.krel")/modules.builtin"
}

# refute <name> <pattern>: the previous check's output must not match.
refute() {
    if grep -qE "$2" <<< "$LAST_OUT"; then
        echo "  FAIL: $1 — output matches '$2'"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: $1"
        PASS=$((PASS + 1))
    fi
}

echo "Kernel version ranges"
r=$(new_root 4.9.0-13-amd64 debian 9);         check "4.9 predates both bugs"       "$r" 0 SAFE
r=$(new_root 7.0.0-10-generic ubuntu 26.04);   check "7.0 has both upstream fixes"  "$r" 0 SAFE
r=$(new_root 5.15.0-100-generic ubuntu 22.04); ship_esp "$r"
check "5.15, esp4/esp6 shipped but not loaded (autoload)" "$r" 1 VULNERABLE

echo "esp4 / esp6 (CVE-2026-43284)"
r=$(new_root 6.8.0-40-generic ubuntu 24.04)
check "esp4 loaded" "$r" 1 VULNERABLE MOCK_LSMOD=esp4

r=$(new_root 6.8.0-40-generic ubuntu 24.04); builtin "$r" kernel/net/ipv4/esp4.ko
check "esp4 built in, absent from lsmod" "$r" 1 VULNERABLE

r=$(new_root 6.8.0-40-generic ubuntu 24.04); builtin "$r" kernel/net/ipv6/esp6.ko
check "esp6 built in, absent from lsmod" "$r" 1 VULNERABLE

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
check "esp4/esp6 not shipped for this kernel" "$r" 2 MITIGATED

r=$(new_root 6.8.0-40-generic ubuntu 24.04); ship_esp "$r"
printf 'install esp4 /bin/false\ninstall esp6 /bin/false\n' > "$r/etc/modprobe.d/dirtyfrag.conf"
check "esp4/esp6 shipped, blacklisted, not loaded" "$r" 2 MITIGATED

r=$(new_root 6.8.0-40-generic ubuntu 24.04); ship_esp "$r"
echo "install esp4 /bin/false" > "$r/etc/modprobe.d/dirtyfrag.conf"
check "only esp4 blacklisted, esp6 still loadable" "$r" 1 VULNERABLE

r=$(new_root 6.8.0-40-generic ubuntu 24.04); ship_esp "$r"
check "shipped, not loaded, kernel.modules_disabled=1" "$r" 2 MITIGATED \
    MOCK_SYSCTL_kernel_modules_disabled=1

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
printf 'install esp4 /bin/false\ninstall esp6 /bin/false\n' > "$r/etc/modprobe.d/dirtyfrag.conf"
check "esp4 blacklisted but still loaded" "$r" 1 VULNERABLE MOCK_LSMOD=esp4

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
check "KernelCare live patch covers loaded esp4" "$r" 2 MITIGATED MOCK_LSMOD=esp4 \
    DIRTYFRAG_TEST_PATH="${MOCK_KCARE}:${MOCK_BIN}" MOCK_KCARE_INFO="CVE-2026-43284 dirtyfrag-esp"

echo "rxrpc (CVE-2026-43500)"
r=$(new_root 6.8.0-40-generic ubuntu 24.04); add_ko "$r" kernel/net/rxrpc/rxrpc.ko
check "rxrpc shipped and loaded" "$r" 1 VULNERABLE MOCK_LSMOD=rxrpc

r=$(new_root 6.8.0-40-generic ubuntu 24.04); builtin "$r" kernel/net/rxrpc/rxrpc.ko
check "rxrpc built in, absent from lsmod" "$r" 1 VULNERABLE

r=$(new_root 6.8.0-40-generic ubuntu 24.04); add_ko "$r" kernel/net/rxrpc/rxrpc.ko.zst
check "rxrpc.ko.zst shipped, not loaded (autoload)" "$r" 1 VULNERABLE
refute "rxrpc.ko.zst is detected as shipped" 'rxrpc module not present'

r=$(new_root 6.8.0-40-generic ubuntu 24.04); add_ko "$r" kernel/net/rxrpc/rxrpc.ko.zst
echo "install rxrpc /bin/false" > "$r/etc/modprobe.d/dirtyfrag.conf"
check "rxrpc shipped and blacklisted, esp not shipped" "$r" 2 MITIGATED

echo "RHEL vendor kernels"
r=$(new_root 4.18.0-553.123.2.el8_10.x86_64 almalinux 8.10)
check "RHEL 8 with the vendor fix" "$r" 0 SAFE
refute "RHEL 8 vendor fix drops the upstream-range issue" 'lacks upstream fix'
r=$(new_root 4.18.0-553.100.1.el8_10.x86_64 almalinux 8.10); ship_esp "$r"
check "RHEL 8 without the vendor fix" "$r" 1 VULNERABLE
r=$(new_root 5.14.0-620.el9.x86_64 almalinux 9.6); ship_esp "$r"
check "RHEL 9 placeholder threshold does not clear the verdict" "$r" 1 VULNERABLE

echo "Hardening"
r=$(new_root 6.8.0-40-generic ubuntu 24.04)
printf 'NAME="Evil$(touch %s/pwned)"\nID=ubuntu\nVERSION_ID="24.04"\n`touch %s/pwned2`\n' \
    "$TMP" "$TMP" > "$r/etc/os-release"
check "os-release is parsed, not executed" "$r" 2 MITIGATED
if compgen -G "${TMP}/pwned*" > /dev/null; then
    echo "  FAIL: code embedded in os-release was executed"
    FAIL=$((FAIL + 1))
fi

echo
echo "${PASS} passed, ${FAIL} failed."
[[ $FAIL -eq 0 ]]
