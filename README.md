# dirtyfrag-audit

![CVE-2026-43284](https://img.shields.io/badge/CVE--2026--43284-esp4%2Fesp6-red?style=flat-square)
![CVE-2026-43500](https://img.shields.io/badge/CVE--2026--43500-rxrpc-red?style=flat-square)
![CVSS ESP](https://img.shields.io/badge/CVSS-8.8%20HIGH-orange?style=flat-square)
![Shell](https://img.shields.io/badge/shell-bash-4EAA25?style=flat-square&logo=gnu-bash)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Disclosed](https://img.shields.io/badge/disclosed-2026--05--07-yellow?style=flat-square)

Audit script for **CVE-2026-43284 + CVE-2026-43500 "Dirty Frag"** — a chained Linux kernel local privilege escalation vulnerability disclosed on 2026-05-07 with a working public exploit, before distribution patches were available.

> Also known as **"Copy Fail 2: Electric Boogaloo"** — same code paths, different exploit author.

---

## What is Dirty Frag?

Dirty Frag chains two distinct kernel bugs discovered by [Hyunwoo Kim (@v4bel)](https://github.com/v4bel), each targeting the same vulnerability class — **in-place decryption over paged buffers not exclusively owned by the kernel**.

### CVE-2026-43284 — xfrm-ESP Page-Cache Write

```
AF_INET / AF_INET6 socket (IPsec ESP)
  └── In-place decryption path (commit cac2661c53f3, Jan 2017)
        └── splice() feeds page cache pages as destination buffers
              └── Plaintext write at attacker-controlled offset in page cache
                    └── Target SUID binary in memory → root
```

- **CVSS:** 8.8 HIGH
- **Modules:** `esp4`, `esp6`
- **Introduced:** January 2017 (same commit as CVE-2022-27666)
- **Mainline fix:** `f4c50a4034e6`

### CVE-2026-43500 — RxRPC Page-Cache Write

```
AF_RXRPC socket (Andrew File System / RxRPC protocol)
  └── Same in-place pattern added to rxrpc (June 2023)
        └── Same page-cache write primitive
              └── root
```

- **CVSS:** 7.8 HIGH
- **Module:** `rxrpc`
- **Introduced:** June 2023
- **Mainline fix:** `aa54b1d27fe0`

### Why it matters

| Property | Dirty Cow (2016) | Dirty Pipe (2022) | Copy Fail (2026) | **Dirty Frag (2026)** |
|---|---|---|---|---|
| Race condition | ✅ Required | ❌ No | ❌ No | ❌ **No** |
| Write granularity | Arbitrary | 1 byte aligned | 4 bytes fixed | **Full plaintext, any offset** |
| Disk modification | ✅ | ❌ | ❌ | ❌ |
| Forensic trace | ✅ | ❌ | ❌ | ❌ |
| Container escape | Limited | Limited | Possible | **Yes (shared page cache)** |
| Public exploit | ✅ | ✅ | ✅ | ✅ **before patches** |
| Attack vectors | 1 | 1 | 1 | **2 (esp + rxrpc)** |

---

## Affected Kernels

### CVE-2026-43284 (esp4/esp6)

| Kernel range | Status |
|---|---|
| < 4.14 | ✅ Not affected |
| **4.14 – latest unpatched** | ❌ **Vulnerable** |
| mainline with `f4c50a4034e6` | ✅ Patched |

### CVE-2026-43500 (rxrpc)

| Kernel range | Status |
|---|---|
| < 6.4 | ✅ Not affected (pattern not introduced yet) |
| **6.4 – latest unpatched** | ❌ **Vulnerable** |
| mainline with `aa54b1d27fe0` | ✅ Patched |

### Distribution Patch Status

| Distribution | CVE-2026-43284 | CVE-2026-43500 | Patched version |
|---|---|---|---|
| AlmaLinux / RHEL 8 | ❌ Affected | ✅ Not shipped | `kernel-4.18.0-553.123.2.el8_10` |
| AlmaLinux / RHEL 9 | ❌ Affected | ⚠ Only if `kernel-modules-partner` (Devel repo) installed | via `dnf upgrade` |
| AlmaLinux / RHEL 10 | ❌ Affected | ❌ Affected | via `dnf upgrade` |
| Ubuntu 20.04–24.04 | ❌ Affected | ⚠ Kernel dependent | via `apt dist-upgrade` |
| Debian stable | ❌ Affected | ⚠ Kernel dependent | Fix only in sid (`linux ≥ 7.0.4-1`) |
| SUSE / openSUSE | ❌ Affected | ❌ Affected | via `zypper update kernel-default` |
| Arch Linux | ❌ Affected | ❌ Affected | via `pacman -Syu linux` |

---

## Usage

```bash
git clone https://github.com/Quaerendir/dirtyfrag-audit
cd dirtyfrag-audit
chmod +x audit_dirtyfrag.sh
./audit_dirtyfrag.sh
```

**Remote one-liner** (verify before running in prod):

```bash
curl -fsSL https://raw.githubusercontent.com/Quaerendir/dirtyfrag-audit/main/audit_dirtyfrag.sh | bash
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Safe — neither CVE applicable |
| `1` | Vulnerable — at least one CVE active with no mitigation |
| `2` | Mitigated — workaround active, patch still required |

---

## What the Script Checks

| Check | CVE |
|---|---|
| Kernel version range (4.14+ for ESP, 6.4+ for rxrpc) | Both |
| Distro-specific patched kernel versions | Both |
| `esp4` / `esp6` module loaded (lsmod) | CVE-2026-43284 |
| `rxrpc` module loaded (lsmod) | CVE-2026-43500 |
| Built-in vs loadable module detection | Both |
| `modprobe.d` blacklist rules (per-module) | Both |
| IPsec XFRM state/policy — active sessions that would break | CVE-2026-43284 |
| kAFS / AFS module in use — active rxrpc consumers | CVE-2026-43500 |
| KernelCare live patch status | Both |
| `/proc/sys/vm/drop_caches` accessibility | Both |
| Container / Docker / Kubernetes context | Both |
| Active logged-in users (multi-tenant risk) | Both |
| SELinux / AppArmor status | Both |
| IPsec/VTI/XFRM interface detection | CVE-2026-43284 |

---

## Mitigation

### Option A — Update the kernel (definitive fix)

```bash
# RHEL / AlmaLinux
dnf clean metadata && dnf upgrade && reboot

# Ubuntu / Debian
apt-get update && apt-get dist-upgrade && reboot

# SUSE
zypper update kernel-default && reboot

# Arch
pacman -Syu linux && reboot
```

### Option B — Blacklist modules + flush page cache

**First, check for active use:**
```bash
ip xfrm state          # IPsec — if output non-empty, blacklisting breaks IPsec
lsmod | grep kafs      # AFS — if loaded, rxrpc is in use
```

**Apply workaround:**
```bash
printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf

rmmod esp4 esp6 rxrpc 2>/dev/null || true

# IMPORTANT: flush page cache to evict any poisoned pages
echo 3 > /proc/sys/vm/drop_caches
```

### Option C — Live patch (no reboot, KernelCare)

```bash
kcarectl --update
kcarectl --patch-info | grep -iE 'CVE-2026-43284|CVE-2026-43500|dirtyfrag'
```

### What blacklisting does NOT affect

`dm-crypt` / `LUKS` · `WireGuard` · `OpenVPN` · `SSH` · `TLS/kTLS` · `OpenSSL` · `GnuTLS`  
IKE daemons (`strongSwan`, `libreswan`) continue to function — only **in-kernel ESP packet processing** is disabled.

---

## Related

- [copyfail-audit](https://github.com/Quaerendir/copyfail-audit) — audit script for CVE-2026-31431 (Copy Fail)

## References

- [oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/05/07/) — Hyunwoo Kim
- [AlmaLinux announcement](https://almalinux.org/blog/2026-05-07-dirty-frag/)
- [Tenable FAQ](https://www.tenable.com/blog/dirty-frag-cve-2026-43284-cve-2026-43500-frequently-asked-questions-linux-kernel-lpe)
- [Sysdig analysis + Falco rule](https://sysdig.com/blog/dirty-frag-cve-2026-43284-and-cve-2026-43500-detecting-unpatched-local-privilege-escalation-via-linux-kernel-esp-and-rxrpc)
- [TuxCare / KernelCare](https://tuxcare.com/blog/dirty-frag-cve-2026-43284-cve-2026-43500-kernelcare-live-patches-released/)
- [Wiz Blog](https://www.wiz.io/blog/dirty-frag-linux-kernel-local-privilege-escalation-via-esp-and-rxrpc)
- [The Hacker News](https://thehackernews.com/2026/05/linux-kernel-dirty-frag-lpe-exploit.html)
- [Microsoft Security Blog (active attack)](https://www.microsoft.com/en-us/security/blog/2026/05/08/active-attack-dirty-frag-linux-vulnerability-expands-post-compromise-risk/)

---

## License

MIT — see [LICENSE](LICENSE)

---

*Quaerendir / Kostur IT SERVICES*
