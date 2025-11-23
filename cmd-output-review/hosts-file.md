# /etc/hosts File

```bash
runner@github-runner:~$ ls -la /etc/hosts
-rw-r--r-- 1 root root 326 Nov 23 22:15 /etc/hosts
runner@github-runner:~$ cat /etc/hosts
127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1	ip6-localhost	ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
runner@github-runner:~$ 
```

## Summary
- Standard localhost configuration
- IPv6 entries for local network configuration
- Last modified: Nov 23 22:15
