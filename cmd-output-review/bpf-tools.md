# BPF Tools

## bpftool prog show

```bash
runner@github-runner:~$ bpftool prog show
Error: can't get next program: Operation not permitted
runner@github-runner:~$ 
```

## Summary
- bpftool requires elevated privileges to inspect BPF programs
- The runner user does not have CAP_BPF or CAP_SYS_ADMIN capabilities
- This is expected in a containerized/sandboxed environment
