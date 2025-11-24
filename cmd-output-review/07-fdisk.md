# fdisk -l Command Output

```bash
runner@github-runner:~$ fdisk -l
fdisk: cannot open /dev/sda: Permission denied
fdisk: cannot open /dev/sdb: Permission denied
```

## Analysis
Access denied - requires elevated privileges to read disk partition information.
