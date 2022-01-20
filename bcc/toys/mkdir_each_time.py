#!/usr/bin/python3

# mkdir_each_time.py
# Author: Guochao
# Created on 17-01-2022

# Print each time of cgroup mkdir

from bcc import BPF

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/kernfs.h>

BPF_HASH(start, u32);

int trace_start(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    start.update(&pid, &ts);

    return 0;
}

int trace_completion(struct pt_regs *ctx, struct kernfs_node *parent_kn) {
    u64 *tsp, delta;
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();

    tsp = start.lookup(&pid);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        bpf_trace_printk("%d\n", delta);
        start.delete(&pid);
    }
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b"cgroup_mkdir", fn_name="trace_start")
b.attach_kretprobe(event=b"cgroup_mkdir", fn_name="trace_completion")

start = 0
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    msg = msg.decode("utf8")
    ns = int(msg)
    print("At time %.2f s: %10d us" % (ts, ns//100))
