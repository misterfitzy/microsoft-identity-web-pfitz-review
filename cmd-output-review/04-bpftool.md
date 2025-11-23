# bpftool prog show Command Output

## Command
```bash
bpftool prog show
```

## Output
```
Error: can't get next program: Operation not permitted
```

## Description
Attempted to show BPF programs but got permission denied. The runner user doesn't have sufficient privileges to view BPF programs.
