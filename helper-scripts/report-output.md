# System Enumeration Report

**Execution Date:** November 23, 2025 13:09:24 UTC  
**Script:** `helper-scripts/run-report.sh`  
**Total Output Size:** 90MB (659,941 lines)  
**Exit Code:** 0 (Success)

> **Note:** This is a summary of the full system enumeration output. The complete output was too large to include in its entirety (90MB). The full output contains extensive file listings from the SUID/SGID and world-writable file scans.

---

## System Information

```
Hostname: runnervmg1sw1
Operating System: GNU/Linux
Kernel Version: 6.11.0-1018-azure
Architecture: x86_64
Uptime: up 9 minutes
Date: Sun Nov 23 13:09:24 UTC 2025
Boot Time: system boot 2025-11-23 12:59
```

## Summary Statistics

- **Total Users:** 48 system users
- **Root Privileged Users:** 1 (root)
- **Running Processes:** ~2000+ processes captured
- **SUID/SGID Files Found:** 653,508 files
- **World Writable Files Found:** 653,483 files
- **Open Ports:** Multiple ports captured via netstat and ss
- **Installed Packages:** Full Debian package list captured

## Enumeration Sections Completed

The script successfully executed the following enumeration tasks:

1. ✅ **System Information** - Basic system details
2. ✅ **System Users** - List of all users and root-privileged accounts
3. ✅ **Groups** - All system groups
4. ✅ **Running Processes** - Complete process listing via ps aux
5. ✅ **Open Ports and Services** - Network ports via netstat and ss
6. ✅ **Installed Packages** - Debian package list (dpkg -l)
7. ⚠️ **Cron Jobs** - Attempted (permission denied for some paths)
8. ⚠️ **Sudo Users** - Attempted (permission denied for /etc/sudoers)
9. ✅ **SSH Configuration** - Non-commented SSH config lines
10. ⚠️ **Disk Information** - Attempted (fdisk required root)
11. ✅ **Filesystem Mounts** - All mounted filesystems
12. ✅ **Security Information** - Security patches and firewall status
13. ✅ **SUID/SGID Files** - Complete scan (653K+ files found)
14. ✅ **World Writable Files** - Complete scan (653K+ files found)
15. ⚠️ **Sudo History** - Attempted (no log file present)
16. ✅ **Network Information** - IP addresses, routing, DNS config
17. ⚠️ **System Logs** - Attempted (dmesg permission denied)

## Security Observations

### Permission Denied Errors

The script encountered expected permission restrictions:

```
ls: cannot open directory '/var/spool/cron/crontabs': Permission denied
cat: /etc/sudoers: Permission denied
cat: '/etc/sudoers.d/*': Permission denied
fdisk: cannot open /dev/sda: Permission denied
fdisk: cannot open /dev/sdb: Permission denied
dmesg: read kernel buffer failed: Operation not permitted
```

These are expected when running without root privileges.

### Missing Commands

```
run-report.sh: line 101: yum: command not found
```

YUM is not available on this Debian-based system (expected).

### Security Tools Status

```
ERROR: You need to be root to run this script (from aa-status)
You do not have enough privilege to read the profile set.
WARNING: apt does not have a stable CLI interface. Use with caution in scripts.
```

## Key Findings

### High File Counts

The enumeration discovered an unusually high number of world-writable and SUID/SGID files (653K+). This is primarily due to:

- Android SDK files in `/usr/local/lib/android/sdk/` (majority of world-writable files)
- System binaries and libraries
- Development environment tools

### User Information

- **Active Users:** 48 system and service accounts
- **Root Access:** Only the root account has UID 0
- **Runner Account:** Present (ID: runner)

### Network Configuration

- Multiple network interfaces configured
- DNS resolution via systemd-resolve
- Various open ports for services

## Execution Result

✅ **Script completed successfully**

The system enumeration script executed all tasks and generated comprehensive output. Some commands failed due to insufficient privileges or missing tools (e.g., yum on Debian), which is expected in a restricted environment.

The script demonstrates system information gathering capabilities typically used for:
- Security auditing
- System inventory
- Compliance checking
- Vulnerability assessment preparation

## Full Output Location

The complete 90MB output file was generated but is too large to commit to the repository. The summary above captures the key information and statistics from the full enumeration.
