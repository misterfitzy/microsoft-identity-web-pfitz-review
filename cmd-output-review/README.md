# Command Output Review

This directory contains the output of various diagnostic commands run during environment verification for issue #12.

## Files

1. **01-pwd.md** - Current working directory
2. **02-mount.md** - Mounted filesystems
3. **03-env.md** - Environment variables (GitHub Actions, development tools, Copilot agent config)
4. **04-ls-temp.md** - GitHub Actions temporary directory listing
5. **05-ls-copilot-action.md** - Copilot developer action source code listing
6. **06-bpftool.md** - BPF program listing attempt (permission denied)
7. **07-ps-auxfww.md** - Process tree
8. **08-capsh.md** - Linux capabilities check
9. **09-curl-pypi.md** - HTTP connectivity test to PyPI
10. **10-ping-8888.md** - ICMP connectivity test (blocked)
11. **11-fdisk.md** - Disk partition listing attempt (permission denied)
12. **12-resolv-conf.md** - DNS configuration (systemd-resolved)
13. **13-etc-hosts.md** - Hosts file

## Key Findings

### Environment
- **Platform**: GitHub Actions runner (Ubuntu 24, Azure cloud - us-east-1)
- **User**: `runner` (UID 1001, GID 1001)
- **Working Directory**: `/home/runner/work/microsoft-identity-web-pfitz-review/microsoft-identity-web-pfitz-review`

### Connectivity
- ✅ HTTP/HTTPS traffic works (curl to pypi.org successful)
- ❌ ICMP traffic blocked (ping to 8.8.8.8 failed)

### Permissions
- Running with minimal Linux capabilities (no elevated privileges)
- Cannot access block devices or BPF programs

### Development Tools
- Java 17 and 21
- Go 1.22, 1.23, and 1.24
- Android SDK
- Docker support

### DNS
- Managed by systemd-resolved
- Local stub resolver at 127.0.0.53
- Search domain: us-east-1.compute.internal
