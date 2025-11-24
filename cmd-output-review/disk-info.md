# Disk Information

## fdisk -l (Requires elevated permissions)

```bash
runner@github-runner:~$ fdisk -l
fdisk: cannot open /dev/sda: Permission denied
fdisk: cannot open /dev/sdb: Permission denied
runner@github-runner:~$ 
```

## Summary
- fdisk requires root/sudo privileges
- The runner user does not have permission to access raw disk devices
- Disk information can be seen from mount output instead (see mount.md)
