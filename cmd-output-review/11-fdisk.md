# fdisk -l Output

```bash
runner@github-runner:~$ fdisk -l
fdisk: cannot open /dev/sda: Permission denied
fdisk: cannot open /dev/sdb: Permission denied
```

## Summary
Unable to list disk partitions due to insufficient permissions. Requires root/sudo access to read block devices.
