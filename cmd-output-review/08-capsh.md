# capsh --print | grep Current Output

```bash
runner@github-runner:~$ capsh --print | grep Current
Current: =
Current IAB:
```

## Summary
Shows current Linux capabilities:
- **Current**: Empty set (no capabilities)
- **Current IAB**: Empty (Inheritable, Ambient, Bounding sets)

This indicates the process is running with minimal privileges.
