# ps auxfww Output (Partial)

```bash
runner@github-runner:~$ ps auxfww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           2  0.0  0.0      0     0 ?        S    21:28   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [pool_workqueue_release]
root           4  0.0  0.0      0     0 ?        I<   21:28   0:00  \_ [kworker/R-rcu_gp]
root           5  0.0  0.0      0     0 ?        I<   21:28   0:00  \_ [kworker/R-sync_wq]
root           6  0.0  0.0      0     0 ?        I<   21:28   0:00  \_ [kworker/R-slub_flushwq]
root           7  0.0  0.0      0     0 ?        I<   21:28   0:00  \_ [kworker/R-netns]
root          10  0.0  0.0      0     0 ?        I<   21:28   0:00  \_ [kworker/0:0H-events_highpri]
root          12  0.0  0.0      0     0 ?        I<   21:28   0:00  \_ [kworker/R-mm_percpu_wq]
root          14  0.0  0.0      0     0 ?        I    21:28   0:00  \_ [kworker/0:1-events]
root          15  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [rcu_tasks_kthread]
root          16  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [rcu_tasks_rude_kthread]
root          17  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [rcu_tasks_trace_kthread]
root          18  0.1  0.0      0     0 ?        S    21:28   0:00  \_ [ksoftirqd/0]
root          19  0.3  0.0      0     0 ?        I    21:28   0:00  \_ [kworker/0:2-events]
root          20  0.0  0.0      0     0 ?        I    21:28   0:00  \_ [rcu_preempt]
root          21  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [migration/0]
root          23  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [cpuhp/0]
root          24  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [cpuhp/1]
root          25  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [migration/1]
root          26  0.0  0.0      0     0 ?        S    21:28   0:00  \_ [ksoftirqd/1]
...
```

## Summary
Shows process tree with kernel threads (kthreadd, kworker, rcu, ksoftirqd, etc.) and system processes. Output truncated for brevity.
