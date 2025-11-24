# DNS Configuration

## /etc/resolv.conf
```bash
runner@github-runner:~$ ls -la /etc/resolv.conf
lrwxrwxrwx 1 root root 39 Sep 17 04:19 /etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf
```

The file is a symlink to `/run/systemd/resolve/stub-resolv.conf`

## /run/systemd/resolve/stub-resolv.conf
```bash
runner@github-runner:~$ ls -la /run/systemd/resolve/stub-resolv.conf
-rw-r--r-- 1 systemd-resolve systemd-resolve 970 Nov 23 22:03 /run/systemd/resolve/stub-resolv.conf
```

### Contents:
```
# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).
# Do not edit.

nameserver 127.0.0.53
options edns0 trust-ad
search us-east-1.compute.internal
```

## /etc/hosts
```bash
runner@github-runner:~$ ls -la /etc/hosts
-rw-r--r-- 1 root root 326 Nov 23 22:15 /etc/hosts
```

### Contents (partial):
```
127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1	ip6-localhost	ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
...
```

## Summary
- DNS is managed by systemd-resolved
- Nameserver: 127.0.0.53 (systemd-resolved stub resolver)
- Search domain: us-east-1.compute.internal (AWS EC2 environment)
- Standard localhost configuration in /etc/hosts
