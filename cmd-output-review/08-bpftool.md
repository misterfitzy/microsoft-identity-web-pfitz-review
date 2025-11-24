# bpftool - BPF Program Inspector

## Command
```bash
bpftool prog show
```

## Output
```
Error: can't get next program: Operation not permitted
```

## Summary
- Access denied to BPF programs
- Requires elevated privileges (CAP_SYS_ADMIN or CAP_BPF)
- Running as non-root user without necessary capabilities
