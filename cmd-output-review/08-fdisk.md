# fdisk -l Command Output

## Command
```bash
fdisk -l
```

## Output
```
fdisk: cannot open /dev/sda: Permission denied
fdisk: cannot open /dev/sdb: Permission denied
```

## Description
Permission denied when trying to list disk partitions. The runner user doesn't have root privileges required to access block devices.
