# Changelog

## [1.0.0] — 2026-05-16

Initial release.

### Checks implemented
- Kernel version range: CVE-2026-43284 (≥ 4.14), CVE-2026-43500 (≥ 6.4)
- Distro-specific patched version check (AlmaLinux/RHEL 8/9/10, Ubuntu, Debian, SUSE, Arch)
- `esp4` / `esp6` / `rxrpc` module state (loaded, built-in, absent)
- modprobe.d blacklist detection per-module with correctness validation
- IPsec XFRM state/policy check (warns if blacklisting would break connectivity)
- kAFS/AFS in-use detection for rxrpc
- KernelCare live patch detection for both CVEs
- `/proc/sys/vm/drop_caches` accessibility check
- Container / Docker / Podman / Kubernetes context
- Active logged-in users (multi-tenant risk indicator)
- SELinux / AppArmor status
- IPsec/VTI/XFRM interface detection

### Exit codes
- `0` — Safe (neither CVE applicable)
- `1` — Vulnerable (at least one CVE active, no mitigation)
- `2` — Mitigated (workaround active, patch still required)
