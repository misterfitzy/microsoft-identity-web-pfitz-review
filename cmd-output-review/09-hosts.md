# /etc/hosts File

## Command
```bash
ls -la /etc/hosts
cat /etc/hosts
```

## Output

### File Info
```
-rw-r--r-- 1 root root 326 Nov 23 22:15 /etc/hosts
```

### Content
```
127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1	ip6-localhost	ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
```

## Summary
Standard hosts file with localhost entries for both IPv4 and IPv6.
