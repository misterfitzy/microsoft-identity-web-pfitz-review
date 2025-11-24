# Disk Information

```bash
runner@github-runner:~$ fdisk -l
fdisk: cannot open /dev/sda: Permission denied
fdisk: cannot open /dev/sdb: Permission denied
```

## Summary
The `fdisk` command requires root privileges to access block devices. Running as the `runner` user without sudo results in permission denied for both /dev/sda and /dev/sdb.

From the `mount` output, we know:
- /dev/sda1: Root filesystem (ext4)
- /dev/sda15: EFI partition (vfat)
- /dev/sda16: Boot partition (ext4)
- /dev/sdb1: Additional data partition mounted at /mnt (ext4)
