# DNS Configuration

## /etc/resolv.conf

```bash
runner@github-runner:~$ ls -la /etc/resolv.conf
lrwxrwxrwx 1 root root 39 Sep 17 04:19 /etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf
```

**Type:** Symbolic link to `/run/systemd/resolve/stub-resolv.conf`

## /run/systemd/resolve/stub-resolv.conf

```bash
runner@github-runner:~$ ls -la /run/systemd/resolve/stub-resolv.conf
-rw-r--r-- 1 systemd-resolve systemd-resolve 970 Nov 23 22:03 /run/systemd/resolve/stub-resolv.conf
```

```bash
runner@github-runner:~$ cat /run/systemd/resolve/stub-resolv.conf
# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
#
# This file might be symlinked as /etc/resolv.conf. If you're looking at
# /etc/resolv.conf and seeing this text, you have followed the symlink.
#
# This is a dynamic resolv.conf file for connecting local clients to the
# internal DNS stub resolver of systemd-resolved. This file lists all
# configured search domains.
#
# Run "resolvectl status" to see details about the uplink DNS servers
# currently in use.
#
# Third party programs should typically not access this file directly, but only
# through the symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a
# different way, replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 127.0.0.53
options edns0 trust-ad
search us-east-1.compute.internal
```

## Summary
- **DNS resolver:** systemd-resolved stub resolver (127.0.0.53)
- **Search domain:** us-east-1.compute.internal
- **Options:** edns0, trust-ad
