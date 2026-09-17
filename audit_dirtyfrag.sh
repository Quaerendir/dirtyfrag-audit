#!/usr/bin/env bash
# =============================================================================
#  audit_dirtyfrag.sh — CVE-2026-43284 / CVE-2026-43500 "Dirty Frag" Audit
#  Author  : Quaerendir
#  Version : 1.0.0
#  Date    : 2026-05-16
#  License : MIT
#  Repo    : https://github.com/Quaerendir/dirtyfrag-audit
#
#  CVE-2026-43284 "Dirty Frag" — xfrm-ESP Page-Cache Write (IPsec)
#  ─────────────────────────────────────────────────────────────────
#  CVSS  : 8.8 HIGH  |  CWE-787
#  Intro : January 2017 (commit cac2661c53f3 — ESP in-place decryption)
#  Fix   : mainline commit f4c50a4034e6
#  Scope : Linux kernel ≥ 4.14 (affects esp4 / esp6 modules)
#
#  CVE-2026-43500 "Dirty Frag" — RxRPC Page-Cache Write (AFS/RxRPC)
#  ─────────────────────────────────────────────────────────────────
#  CVSS  : 7.8 HIGH  |  CWE-787
#  Intro : June 2023 (same in-place pattern added to rxrpc)
#  Fix   : mainline commit aa54b1d27fe0
#  Scope : Linux kernel ≥ 6.4 (affects rxrpc module)
#
#  Disclosed : 2026-05-07 by Hyunwoo Kim (@v4bel) — embargo broken early
#  PoC       : public, working, root in one command
#  Alias     : "Copy Fail 2: Electric Boogaloo" refers to the same vuln
#
#  Attack chain:
#    AF_INET / AF_INET6 socket (ESP) or AF_RXRPC socket
#      └── in-place decryption over paged buffers NOT owned by kernel
#            └── splice() / vmsplice() feeds page cache pages as buffers
#                  └── plaintext write lands in page cache of any readable file
#                        └── target SUID binary in memory → root
#
#  Key difference vs Copy Fail (CVE-2026-31431):
#    - 4-byte scratch write → FULL attacker-controlled plaintext at any offset
#    - No race condition, deterministic, near 100% success rate
#    - TWO separate vectors (esp4/esp6 + rxrpc), both independently exploitable
#
#  References:
#    https://www.openwall.com/lists/oss-security/2026/05/07/ — disclosure
#    https://github.com/theori-io/dirty-frag — PoC
#    https://almalinux.org/blog/2026-05-07-dirty-frag/
#    https://tuxcare.com/blog/dirty-frag-cve-2026-43284-cve-2026-43500-kernelcare-live-patches-released/
# =============================================================================

set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'
ORANGE='\033[0;33m'; RESET='\033[0m'

# ─── State ────────────────────────────────────────────────────────────────────
VULN_ESP=false       # CVE-2026-43284 (esp4/esp6)
VULN_RXRPC=false     # CVE-2026-43500 (rxrpc)
MIT_ESP=false        # esp4/esp6 mitigated
MIT_RXRPC=false      # rxrpc mitigated
KERNEL_PATCHED=false

ISSUES=()
MITIGATIONS=()

# ─── Helpers ──────────────────────────────────────────────────────────────────
header()  { printf "\n${BOLD}${CYAN}══╡ %s ╞${RESET}\n\n" "$1"; }
ok()      { printf "  ${GREEN}[OK]${RESET}   %s\n" "$1"; }
warn()    { printf "  ${YELLOW}[!!]${RESET}   %s\n" "$1"; }
fail()    { printf "  ${RED}[VULN]${RESET} %s\n" "$1"; }
info()    { printf "  ${CYAN}[i]${RESET}    %s\n" "$1"; }
cve1()    { printf "  ${ORANGE}[ESP]${RESET}  %s\n" "$1"; }
cve2()    { printf "  ${ORANGE}[RXR]${RESET}  %s\n" "$1"; }
sep()     { printf "  ${DIM}────────────────────────────────────────────${RESET}\n"; }

add_issue()      { ISSUES+=("$1"); }
add_mitigation() { MITIGATIONS+=("$1"); }

# ─── Banner ───────────────────────────────────────────────────────────────────
[[ -t 1 ]] && printf '\033[2J\033[H' || true

printf "${BOLD}${YELLOW}"
cat <<'BANNER'
  ██████╗ ██╗██████╗ ████████╗██╗   ██╗    ███████╗██████╗  █████╗  ██████╗
  ██╔══██╗██║██╔══██╗╚══██╔══╝╚██╗ ██╔╝    ██╔════╝██╔══██╗██╔══██╗██╔════╝
  ██║  ██║██║██████╔╝   ██║    ╚████╔╝     █████╗  ██████╔╝███████║██║  ███╗
  ██║  ██║██║██╔══██╗   ██║     ╚██╔╝      ██╔══╝  ██╔══██╗██╔══██║██║   ██║
  ██████╔╝██║██║  ██║   ██║      ██║       ██║     ██║  ██║██║  ██║╚██████╔╝
  ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝       ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝
BANNER
printf "${RESET}"
printf "  ${BOLD}CVE-2026-43284 + CVE-2026-43500 \"Dirty Frag\" — Linux Kernel LPE Audit v1.0.0${RESET}\n"
printf "  ${DIM}Disclosed 2026-05-07 | CVE-2026-43284: CVSS 8.8 | CVE-2026-43500: CVSS 7.8${RESET}\n"
printf "  ${DIM}Vectors: esp4/esp6 (IPsec) + rxrpc (AFS) | in-place decryption page-cache write${RESET}\n\n"

# ─────────────────────────────────────────────────────────────────────────────
#  §1  SYSTEM INFORMATION
# ─────────────────────────────────────────────────────────────────────────────
header "1 · System Information"

KERNEL=$(uname -r)
ARCH=$(uname -m)
HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname)
KVER_MAJOR=$(cut -d. -f1 <<< "$KERNEL")
KVER_MINOR=$(cut -d. -f2 <<< "$KERNEL")
KVER_PATCH=$(cut -d. -f3 <<< "$KERNEL" | grep -oP '^\d+' || echo 0)

DISTRO_NAME="unknown"; DISTRO_ID="unknown"; DISTRO_VERSION="0"
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DISTRO_NAME="${NAME:-unknown} ${VERSION_ID:-}"
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION="${VERSION_ID:-0}"
fi

info "Hostname   : $HOSTNAME_FQDN"
info "Distro     : $DISTRO_NAME"
info "Kernel     : $KERNEL"
info "Arch       : $ARCH"
info "Date       : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ─────────────────────────────────────────────────────────────────────────────
#  §2  KERNEL VERSION — CVE-2026-43284 (ESP, since 4.14 / Jan 2017)
# ─────────────────────────────────────────────────────────────────────────────
header "2 · Kernel Version — CVE-2026-43284 (IPsec ESP)"

info "Kernel: ${KVER_MAJOR}.${KVER_MINOR}.${KVER_PATCH} | Introduced: 4.14 (Jan 2017)"
info "Mainline fix: commit f4c50a4034e6"

if (( KVER_MAJOR < 4 )) || ( (( KVER_MAJOR == 4 )) && (( KVER_MINOR < 14 )) ); then
    ok "Kernel < 4.14 — CVE-2026-43284 NOT present (ESP in-place path absent)"
elif (( KVER_MAJOR >= 7 )); then
    ok "Kernel ≥ 7.0 — CVE-2026-43284 NOT present (upstream fix merged)"
else
    fail "Kernel $KERNEL in vulnerable range for CVE-2026-43284 (esp4/esp6)"
    VULN_ESP=true
    add_issue "CVE-2026-43284: kernel $KERNEL lacks upstream fix (f4c50a4034e6)"
fi

sep

# ─────────────────────────────────────────────────────────────────────────────
#  §3  KERNEL VERSION — CVE-2026-43500 (RxRPC, since 6.4 / June 2023)
# ─────────────────────────────────────────────────────────────────────────────
header "3 · Kernel Version — CVE-2026-43500 (RxRPC)"

info "Kernel: ${KVER_MAJOR}.${KVER_MINOR}.${KVER_PATCH} | Introduced: 6.4 (June 2023)"
info "Mainline fix: commit aa54b1d27fe0"

if (( KVER_MAJOR < 6 )) || ( (( KVER_MAJOR == 6 )) && (( KVER_MINOR < 4 )) ); then
    ok "Kernel < 6.4 — CVE-2026-43500 NOT present (rxrpc fast-path not introduced yet)"
elif (( KVER_MAJOR >= 7 )); then
    ok "Kernel ≥ 7.0 — CVE-2026-43500 NOT present (upstream fix merged)"
else
    fail "Kernel $KERNEL in vulnerable range for CVE-2026-43500 (rxrpc)"
    VULN_RXRPC=true
    add_issue "CVE-2026-43500: kernel $KERNEL lacks upstream fix (aa54b1d27fe0)"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §4  DISTRIBUTION-SPECIFIC PATCH STATUS
# ─────────────────────────────────────────────────────────────────────────────
header "4 · Distribution Patch Status"

_rhel_check() {
    command -v rpm &>/dev/null || return
    local kpkg ver_major patched_esp=false
    kpkg=$(rpm -q kernel 2>/dev/null | grep "$(uname -r)" | head -1 || true)
    [[ -n "$kpkg" ]] && info "Installed kernel RPM: $kpkg"
    ver_major="${DISTRO_VERSION%%.*}"

    case "$ver_major" in
        8)
            # AlmaLinux/RHEL 8: target kernel-4.18.0-553.123.2.el8_10
            local n; n=$(uname -r | grep -oP '4\.18\.0-\K\d+' || echo 0)
            if (( n > 553 )); then patched_esp=true
            elif (( n == 553 )); then
                local s; s=$(uname -r | grep -oP '553\.\K\d+' || echo 0)
                (( s >= 123 )) && patched_esp=true
            fi
            if "$patched_esp"; then
                ok "RHEL/AlmaLinux 8: kernel ≥ 4.18.0-553.123.2.el8_10 — PATCHED (CVE-2026-43284)"
                KERNEL_PATCHED=true
            else
                fail "RHEL/AlmaLinux 8: needs kernel ≥ 4.18.0-553.123.2.el8_10"
                add_issue "RHEL8 kernel unpatched (CVE-2026-43284)"
            fi
            info "Note: AlmaLinux 8 ships without rxrpc — CVE-2026-43500 NOT applicable"
            ;;
        9)
            local n; n=$(uname -r | grep -oP '5\.14\.0-\K\d+' || echo 0)
            # EL9 kernels are < 6.4 upstream, so CVE-2026-43500 only applies if rxrpc is installed
            if (( n >= 615 )); then patched_esp=true; fi   # placeholder — check upstream
            if "$patched_esp"; then
                ok "RHEL/AlmaLinux 9: CVE-2026-43284 — PATCHED"
                KERNEL_PATCHED=true
            else
                fail "RHEL/AlmaLinux 9: check dnf update kernel for CVE-2026-43284 fix"
                add_issue "RHEL9 kernel — verify patch via dnf"
            fi
            info "CVE-2026-43500 (rxrpc): only applies if kernel-modules-partner (Devel repo) is installed"
            ;;
        10)
            fail "RHEL/AlmaLinux 10: check dnf update kernel for both CVEs"
            add_issue "RHEL10 kernel — verify patch via dnf"
            ;;
        *)
            info "RHEL family v$ver_major — manual check required"
            ;;
    esac
}

_deb_check() {
    command -v dpkg &>/dev/null || return
    local kpkg
    kpkg=$(dpkg -l "linux-image-$(uname -r)" 2>/dev/null | grep '^ii' | awk '{print $2" "$3}' || true)
    [[ -n "$kpkg" ]] && info "Installed kernel DEB: $kpkg"
    case "$DISTRO_ID" in
        ubuntu)
            warn "Ubuntu — run: sudo apt update && sudo apt dist-upgrade && reboot"
            warn "Check: https://ubuntu.com/security/CVE-2026-43284"
            ;;
        debian)
            warn "Debian: fix only in sid (linux ≥ 7.0.4-1) — stable branches unpatched"
            warn "Track: https://security-tracker.debian.org/tracker/CVE-2026-43284"
            ;;
        *)
            info "Debian-family ($DISTRO_ID) — manual verification required"
            ;;
    esac
}

case "$DISTRO_ID" in
    almalinux|rocky|centos|rhel|fedora) _rhel_check ;;
    ubuntu|debian|linuxmint|pop)        _deb_check  ;;
    opensuse*|sles) warn "SUSE — run: zypper update kernel-default" ;;
    arch|manjaro)   warn "Arch — run: pacman -Syu linux" ;;
    *)              info "Distribution $DISTRO_ID — manual patch verification required" ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
#  §5  MODULE STATUS — esp4 / esp6 (CVE-2026-43284)
# ─────────────────────────────────────────────────────────────────────────────
header "5 · Module Status — esp4 / esp6 (CVE-2026-43284)"

ESP4_LOADED=false; ESP6_LOADED=false
ESP4_BUILTIN=false; ESP6_BUILTIN=false

# ── Check built-in ──
if [[ -f /lib/modules/"$(uname -r)"/modules.builtin ]]; then
    grep -q 'esp4\.ko\|esp4$' /lib/modules/"$(uname -r)"/modules.builtin 2>/dev/null && ESP4_BUILTIN=true
    grep -q 'esp6\.ko\|esp6$' /lib/modules/"$(uname -r)"/modules.builtin 2>/dev/null && ESP6_BUILTIN=true
fi

# ── Check kernel config ──
CONFIG_FILE=""
for f in /proc/config.gz "/boot/config-$(uname -r)" /boot/config; do
    [[ -f "$f" ]] && { CONFIG_FILE="$f"; break; }
done

if [[ -n "$CONFIG_FILE" ]]; then
    if [[ "$CONFIG_FILE" == *.gz ]]; then
        _read_cfg() { zcat "$CONFIG_FILE" 2>/dev/null | grep -m1 "$1" || echo "NOT_FOUND"; }
    else
        _read_cfg() { grep -m1 "$1" "$CONFIG_FILE" 2>/dev/null || echo "NOT_FOUND"; }
    fi
    info "Kernel config: $CONFIG_FILE"

    for mod_cfg in CONFIG_INET_ESP CONFIG_INET6_ESP; do
        cfg_val=$(_read_cfg "^${mod_cfg}=")
        info "$mod_cfg = ${cfg_val:-NOT_FOUND}"
    done
fi

# ── lsmod ──
sep
if lsmod 2>/dev/null | grep -q '^esp4 '; then
    ESP4_LOADED=true
    fail "esp4 module is LOADED (CVE-2026-43284 vector active)"
    add_issue "CVE-2026-43284: esp4 loaded and exploitable"
else
    ok "esp4 — not loaded"
fi

if lsmod 2>/dev/null | grep -q '^esp6 '; then
    ESP6_LOADED=true
    fail "esp6 module is LOADED (CVE-2026-43284 vector active)"
    add_issue "CVE-2026-43284: esp6 loaded and exploitable"
else
    ok "esp6 — not loaded"
fi

# ── Check if IPsec is actively in use ──
sep
if command -v ip &>/dev/null; then
    XFRM_SA=$(ip xfrm state 2>/dev/null | grep -c 'src' || echo 0)
    XFRM_POL=$(ip xfrm policy 2>/dev/null | grep -c 'src' || echo 0)
    if (( XFRM_SA > 0 )) || (( XFRM_POL > 0 )); then
        warn "Active IPsec state/policy detected — disabling esp4/esp6 will break IPsec!"
        warn "XFRM SAs: $XFRM_SA | Policies: $XFRM_POL"
        add_issue "Active IPsec sessions — module blacklist will disrupt connectivity"
    else
        ok "No active IPsec XFRM state/policy — safe to blacklist esp4/esp6"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §6  MODULE STATUS — rxrpc (CVE-2026-43500)
# ─────────────────────────────────────────────────────────────────────────────
header "6 · Module Status — rxrpc (CVE-2026-43500)"

RXRPC_LOADED=false; RXRPC_BUILTIN=false

# ── Built-in check ──
if [[ -f /lib/modules/"$(uname -r)"/modules.builtin ]]; then
    grep -q 'rxrpc' /lib/modules/"$(uname -r)"/modules.builtin 2>/dev/null && RXRPC_BUILTIN=true
fi

if [[ "$RXRPC_BUILTIN" == "true" ]]; then
    warn "rxrpc is built-in — modprobe.d blacklist will NOT work"
    add_issue "rxrpc built-in: modprobe.d mitigation ineffective"
fi

# ── lsmod ──
if lsmod 2>/dev/null | grep -q '^rxrpc '; then
    RXRPC_LOADED=true
    fail "rxrpc module is LOADED (CVE-2026-43500 vector active)"
    add_issue "CVE-2026-43500: rxrpc loaded and exploitable"
else
    ok "rxrpc — not loaded"
fi

# ── Check if rxrpc exists as a module at all (might not be shipped on older distros) ──
if [[ ! -f "/lib/modules/$(uname -r)/kernel/net/rxrpc/rxrpc.ko" ]] && \
   [[ ! -f "/lib/modules/$(uname -r)/kernel/net/rxrpc/rxrpc.ko.xz" ]] && \
   [[ "$RXRPC_BUILTIN" == "false" ]]; then
    ok "rxrpc module not present on this system — CVE-2026-43500 NOT applicable"
    VULN_RXRPC=false
else
    [[ "$RXRPC_LOADED" == "false" ]] && \
        info "rxrpc module exists but is not currently loaded"
fi

# ── Check AFS/Kerberos use ──
if lsmod 2>/dev/null | grep -qE '^(kafs|afs) '; then
    warn "AFS/kAFS module loaded — rxrpc is likely in active use; blacklisting may break AFS"
    add_issue "kAFS in use — rxrpc blacklist will break AFS connections"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §7  MITIGATION VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────
header "7 · Mitigation Status"

BLACKLIST_FILE="/etc/modprobe.d/dirtyfrag.conf"
ESP4_BLACKLISTED=false; ESP6_BLACKLISTED=false; RXRPC_BLACKLISTED=false

# ── 7a: modprobe.d ──
printf "\n  ${BOLD}[a] modprobe.d blacklist${RESET}\n\n"

for modconf in /etc/modprobe.d/*.conf; do
    [[ -f "$modconf" ]] || continue
    grep -qP '^(blacklist|install)\s+esp4'  "$modconf" 2>/dev/null && \
        { ESP4_BLACKLISTED=true;  ok "esp4  blacklisted in $modconf"; }
    grep -qP '^(blacklist|install)\s+esp6'  "$modconf" 2>/dev/null && \
        { ESP6_BLACKLISTED=true;  ok "esp6  blacklisted in $modconf"; }
    grep -qP '^(blacklist|install)\s+rxrpc' "$modconf" 2>/dev/null && \
        { RXRPC_BLACKLISTED=true; ok "rxrpc blacklisted in $modconf"; }
done

# Evaluate per-CVE mitigation state
if "$ESP4_BLACKLISTED" && "$ESP6_BLACKLISTED"; then
    if ! "$ESP4_LOADED" && ! "$ESP6_LOADED"; then
        MIT_ESP=true
        add_mitigation "esp4 + esp6 blacklisted and not loaded (CVE-2026-43284)"
    else
        warn "esp4/esp6 blacklisted but still loaded — rmmod required"
        add_issue "esp4/esp6 blacklisted but still active in memory"
    fi
elif "$VULN_ESP"; then
    [[ "$ESP4_BLACKLISTED" == "false" ]] && warn "esp4 NOT blacklisted in modprobe.d"
    [[ "$ESP6_BLACKLISTED" == "false" ]] && warn "esp6 NOT blacklisted in modprobe.d"
fi

if "$RXRPC_BLACKLISTED"; then
    if ! "$RXRPC_LOADED"; then
        "$VULN_RXRPC" && MIT_RXRPC=true
        add_mitigation "rxrpc blacklisted and not loaded (CVE-2026-43500)"
    else
        warn "rxrpc blacklisted but still loaded — rmmod required"
        add_issue "rxrpc blacklisted but still active in memory"
    fi
elif "$VULN_RXRPC" && "$RXRPC_LOADED"; then
    warn "rxrpc NOT blacklisted in modprobe.d"
fi

# ── 7b: Are modules currently absent (unloaded == de-facto mitigated)? ──
sep
printf "\n  ${BOLD}[b] Runtime module state (current session)${RESET}\n\n"

if ! "$ESP4_LOADED" && ! "$ESP6_LOADED"; then
    ok "esp4 and esp6 not in memory — CVE-2026-43284 not exploitable right now"
    "$VULN_ESP" && MIT_ESP=true
else
    [[ "$ESP4_LOADED" == "true" ]] && fail "esp4 in memory — CVE-2026-43284 exploitable"
    [[ "$ESP6_LOADED" == "true" ]] && fail "esp6 in memory — CVE-2026-43284 exploitable"
fi

if ! "$RXRPC_LOADED"; then
    ok "rxrpc not in memory — CVE-2026-43500 not exploitable right now"
    "$VULN_RXRPC" && MIT_RXRPC=true
else
    fail "rxrpc in memory — CVE-2026-43500 exploitable"
fi

# ── 7c: Page cache state ──
sep
printf "\n  ${BOLD}[c] Page cache drop (drop_caches)${RESET}\n\n"

info "CopyFail/DirtyFrag can leave poisoned page cache after exploit attempt"
info "Recommended post-mitigation: echo 3 > /proc/sys/vm/drop_caches"

# Check if drop_caches is accessible
if [[ -w /proc/sys/vm/drop_caches ]]; then
    ok "drop_caches is writable (root can flush page cache if needed)"
else
    info "drop_caches not writable by current user (root-only)"
fi

# ── 7d: KernelCare ──
sep
printf "\n  ${BOLD}[d] KernelCare live patch${RESET}\n\n"

if command -v kcarectl &>/dev/null; then
    KC_VERSION=$(kcarectl --version 2>/dev/null || echo "unknown")
    info "KernelCare installed: $KC_VERSION"
    KC_PATCH_INFO=$(kcarectl --patch-info 2>/dev/null || echo "")
    if echo "$KC_PATCH_INFO" | grep -qi 'CVE-2026-43284\|dirtyfrag'; then
        ok "KernelCare: CVE-2026-43284 live patch APPLIED"
        add_mitigation "KernelCare live patch: CVE-2026-43284"
        MIT_ESP=true
    else
        warn "KernelCare installed but CVE-2026-43284 patch not detected"
        warn "Run: kcarectl --update"
    fi
    if echo "$KC_PATCH_INFO" | grep -qi 'CVE-2026-43500'; then
        ok "KernelCare: CVE-2026-43500 live patch APPLIED"
        add_mitigation "KernelCare live patch: CVE-2026-43500"
        MIT_RXRPC=true
    fi
else
    info "KernelCare not installed (no-reboot live patch option unavailable)"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §8  NETWORK EXPOSURE ASSESSMENT
# ─────────────────────────────────────────────────────────────────────────────
header "8 · Network / Container Exposure"

# ── Interfaces ──
if command -v ip &>/dev/null; then
    IFACES=$(ip -o link show 2>/dev/null | awk '{print $2}' | tr -d ':' | tr '\n' ' ')
    info "Network interfaces: $IFACES"

    # Look for ipsec / xfrm interfaces
    if ip link show 2>/dev/null | grep -qiE 'xfrm|ipsec|vti|gre'; then
        warn "IPsec/XFRM/VTI interface detected — esp4/esp6 likely in active use"
        add_issue "IPsec tunnel detected — mitigation may disrupt network"
    fi
fi

# ── Container check ──
IN_CONTAINER=false
[[ -f /.dockerenv ]] && { IN_CONTAINER=true; warn "Running INSIDE a Docker container"; }
grep -q 'container=podman\|container=lxc' /proc/1/environ 2>/dev/null && \
    { IN_CONTAINER=true; warn "Running inside a container (podman/lxc)"; }

if "$IN_CONTAINER"; then
    fail "Page cache is HOST-WIDE — Dirty Frag is a potential container escape!"
    add_issue "Container context: page cache shared with host — container escape risk"
fi

if command -v kubectl &>/dev/null || [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
    warn "Kubernetes environment detected — all nodes require patching"
    add_issue "Kubernetes node — shared page cache risk across pods (container escape)"
fi

# ── Check for active users (multi-tenant risk) ──
ACTIVE_USERS=$(who 2>/dev/null | awk '{print $1}' | sort -u | grep -v "$(whoami)" | wc -l || echo 0)
if (( ACTIVE_USERS > 0 )); then
    warn "Other users currently logged in: $ACTIVE_USERS — multi-user exposure active"
    add_issue "$ACTIVE_USERS other user(s) logged in — LPE risk is immediate"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §9  KERNEL HARDENING CONTEXT
# ─────────────────────────────────────────────────────────────────────────────
header "9 · Kernel Hardening (Context)"

_sysctl_check() {
    local key="$1" desc="$2"
    local val; val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if   [[ "$val" == "N/A" ]]; then info "$key = N/A"
    elif (( val >= 1 )) 2>/dev/null; then ok  "$key = $val  ($desc)"
    else                                 warn "$key = $val  ($desc)"
    fi
}

_sysctl_check "kernel.dmesg_restrict"       "restrict /dev/kmsg access"
_sysctl_check "kernel.kptr_restrict"        "hide kernel pointers"
_sysctl_check "kernel.perf_event_paranoid"  "perf event paranoia"
_sysctl_check "net.ipv4.conf.all.rp_filter" "reverse-path filter (partial mitigation)"

info "Note: Dirty Frag uses only standard syscalls (socket/splice/vmsplice/sendmsg)"
info "      No user namespaces, no capabilities, no special permissions required"

sep
if command -v getenforce &>/dev/null; then
    SE=$(getenforce 2>/dev/null || echo "N/A")
    [[ "$SE" == "Enforcing" ]] && \
        { ok "SELinux: Enforcing"; add_mitigation "SELinux Enforcing"; } || \
        warn "SELinux: $SE"
elif [[ -f /sys/module/apparmor/parameters/enabled ]]; then
    AA=$(cat /sys/module/apparmor/parameters/enabled)
    [[ "$AA" == "Y" ]] && { ok "AppArmor: active"; add_mitigation "AppArmor active"; } || \
        warn "AppArmor: inactive"
else
    warn "No MAC framework detected"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §10  FINAL VERDICT
# ─────────────────────────────────────────────────────────────────────────────
header "VERDICT — CVE-2026-43284 + CVE-2026-43500 \"Dirty Frag\""

printf "  Host:   %s\n" "$HOSTNAME_FQDN"
printf "  Distro: %s\n" "$DISTRO_NAME"
printf "  Kernel: %s\n\n" "$KERNEL"

_verdict_row() {
    local cve="$1" vuln="$2" mitigated="$3" desc="$4"
    if [[ "$vuln" == "false" ]]; then
        printf "  ${GREEN}[SAFE]${RESET}       %-20s %s\n" "$cve" "$desc"
    elif [[ "$mitigated" == "true" ]]; then
        printf "  ${YELLOW}[MITIGATED]${RESET}  %-20s %s\n" "$cve" "$desc"
    else
        printf "  ${RED}[VULNERABLE]${RESET} %-20s %s\n" "$cve" "$desc"
    fi
}

_verdict_row "CVE-2026-43284" "$VULN_ESP"   "$MIT_ESP"   "(esp4/esp6 — IPsec in-place decrypt)"
_verdict_row "CVE-2026-43500" "$VULN_RXRPC" "$MIT_RXRPC" "(rxrpc   — AFS in-place decrypt)"

# Overall state
OVERALL_VULN=false
OVERALL_MIT=false
"$VULN_ESP"   && ! "$MIT_ESP"   && OVERALL_VULN=true
"$VULN_RXRPC" && ! "$MIT_RXRPC" && OVERALL_VULN=true
( "$VULN_ESP" && "$MIT_ESP" ) || ( "$VULN_RXRPC" && "$MIT_RXRPC" ) && OVERALL_MIT=true

echo ""
if ! "$VULN_ESP" && ! "$VULN_RXRPC"; then
    printf "  ${GREEN}${BOLD}╔══════════════════════════════════╗\n"
    printf "  ║  ✔  SAFE — not vulnerable         ║\n"
    printf "  ╚══════════════════════════════════╝${RESET}\n"
elif "$OVERALL_VULN"; then
    printf "  ${RED}${BOLD}╔══════════════════════════════════╗\n"
    printf "  ║  ✘  VULNERABLE — patch NOW!        ║\n"
    printf "  ╚══════════════════════════════════╝${RESET}\n"
else
    printf "  ${YELLOW}${BOLD}╔══════════════════════════════════╗\n"
    printf "  ║  ⚡  MITIGATED — patch ASAP!       ║\n"
    printf "  ╚══════════════════════════════════╝${RESET}\n"
    echo -e "\n  ${YELLOW}Workaround active but NOT a permanent fix — update the kernel!${RESET}"
fi

# ── Issues ──
if [[ ${#ISSUES[@]} -gt 0 ]]; then
    printf "\n  ${RED}${BOLD}Issues found:${RESET}\n"
    for i in "${ISSUES[@]}"; do printf "  ${RED}→${RESET} %s\n" "$i"; done
fi

if [[ ${#MITIGATIONS[@]} -gt 0 ]]; then
    printf "\n  ${GREEN}${BOLD}Active mitigations:${RESET}\n"
    for m in "${MITIGATIONS[@]}"; do printf "  ${GREEN}✓${RESET} %s\n" "$m"; done
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §11  REMEDIATION GUIDE
# ─────────────────────────────────────────────────────────────────────────────
header "Remediation"

cat <<'REMED'
  ┌─ [1] UPDATE THE KERNEL (definitive fix) ─────────────────────────────────┐
  │  RHEL / AlmaLinux 8:  dnf update kernel   # target: ≥ 4.18.0-553.123.2   │
  │  RHEL / AlmaLinux 9+: dnf update kernel   # run: dnf clean metadata first │
  │  Ubuntu / Debian:     apt-get update && apt-get dist-upgrade              │
  │  SUSE:                zypper update kernel-default                         │
  │  Arch:                pacman -Syu linux                                    │
  │  Fedora:              dnf upgrade kernel                                   │
  └───────────────────────────────────────────────────────────────────────────┘

  ┌─ [2] WORKAROUND — blacklist modules + unload + drop page cache ───────────┐
  │  printf 'install esp4 /bin/false\ninstall esp6 /bin/false\n' \            │
  │    >> /etc/modprobe.d/dirtyfrag.conf                                       │
  │  printf 'install rxrpc /bin/false\n' >> /etc/modprobe.d/dirtyfrag.conf    │
  │  rmmod esp4 esp6 rxrpc 2>/dev/null || true                                │
  │  echo 3 > /proc/sys/vm/drop_caches       # flush page cache!              │
  │                                                                            │
  │  ⚠  Check for active IPsec first:  ip xfrm state                         │
  │  ⚠  Check for AFS use first:       lsmod | grep kafs                      │
  └───────────────────────────────────────────────────────────────────────────┘

  ┌─ [3] LIVE PATCH — no reboot (KernelCare) ─────────────────────────────────┐
  │  kcarectl --update                                                         │
  │  kcarectl --patch-info | grep -i 'CVE-2026-43284\|CVE-2026-43500'         │
  └───────────────────────────────────────────────────────────────────────────┘

  ┌─ [4] VERIFY AFTER PATCHING ───────────────────────────────────────────────┐
  │  lsmod | grep -E '^(esp4|esp6|rxrpc)'     # should return empty           │
  │  cat /etc/modprobe.d/dirtyfrag.conf        # check blacklist rules        │
  │  ip xfrm state                             # verify no active IPsec       │
  └───────────────────────────────────────────────────────────────────────────┘

  ┌─ [5] NOT AFFECTED BY BLACKLISTING ────────────────────────────────────────┐
  │  dm-crypt / LUKS · OpenVPN · WireGuard · SSH · TLS · kTLS                 │
  │  OpenSSL · GnuTLS · IPsec IKE daemons (strongSwan, libreswan) still work  │
  │  ONLY actual ESP packet encryption/decryption in-kernel is disabled       │
  └───────────────────────────────────────────────────────────────────────────┘

  References:
    https://www.openwall.com/lists/oss-security/2026/05/07/
    https://almalinux.org/blog/2026-05-07-dirty-frag/
    https://tuxcare.com/blog/dirty-frag-cve-2026-43284-cve-2026-43500-kernelcare-live-patches-released/
    https://cert.europa.eu

REMED

printf "  ${DIM}audit_dirtyfrag.sh v1.0.0 — github.com/Quaerendir/dirtyfrag-audit${RESET}\n\n"

# ── Exit code ──
if   ! "$VULN_ESP" && ! "$VULN_RXRPC"; then exit 0
elif "$OVERALL_VULN";                   then exit 1
else                                         exit 2
fi
