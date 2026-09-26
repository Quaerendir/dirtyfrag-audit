# Changelog

## [1.1.0] — 2026-09-26

### Changed — verdicts (review before relying on exit codes)
- An unloaded esp4/esp6/rxrpc module is no longer counted as MITIGATED just for being absent from memory. These modules autoload on demand, so they count only when they cannot load: not shipped, blocked in `modprobe.d`, or `kernel.modules_disabled=1`. A typical unpatched host is now VULNERABLE (exit 1) instead of MITIGATED (exit 2).
- Built-in esp4/esp6/rxrpc, which never appear in `lsmod`, are treated as loaded, so VULNERABLE, and a `modprobe.d` blacklist is noted as ineffective for them.
- A patched RHEL 8 vendor kernel (≥ 4.18.0-553.123.2) is now SAFE. The RHEL 9 threshold is still a placeholder and does not clear the verdict.

### Fixed
- `rxrpc.ko.zst` (current Ubuntu) was not recognised, so CVE-2026-43500 was wrongly reported "NOT applicable"; any `.ko*` compression is now detected.
- `grep -c … || echo 0` produced `0` twice and bash arithmetic errors on every clean host.

### Security
- `PATH` is pinned, and the shebang is `#!/bin/bash` instead of `/usr/bin/env bash`.
- `/etc/os-release` is parsed as text instead of sourced, so embedded shell code is never executed.

### Added
- Regression tests (`tests/run_tests.sh`) with mock commands (including KernelCare) and fixture trees.
- CI: syntax check, tests and ShellCheck.

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
