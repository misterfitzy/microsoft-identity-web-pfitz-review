# bpftool prog show Output

```bash
runner@github-runner:~$ bpftool prog show
Error: can't get next program: Operation not permitted
```

## Summary
Unable to list BPF programs due to insufficient permissions. This requires elevated privileges (CAP_SYS_ADMIN or CAP_BPF capability).
