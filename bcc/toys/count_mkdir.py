#!/usr/bin/python3

# count_mkdir.py
# Author: Guochao
# Created on 17-01-2022

# Print timing of mkdir

from bcc import BPF

program = r"""
#include <uapi/linux/ptrace.h>

BPF_HASH(count);

int do_trace(struct pt_regs *ctx) {
    u64 c1 = 1, *cnt, delta, key = 1;
    
    cnt = count.lookup(&key);
    if (cnt != NULL) {
        c1 = *cnt + 1;
    }
    count.update(&key, &c1);
    bpf_trace_printk("%d\n", c1);
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("mkdir"), fn_name="do_trace")

start = 0
while 1:
    (task, pid, cpu, flags, ts, cnt) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    cnt = cnt.decode("utf8")
    print("At time %.2f s: mkdir detected, count: %s" % (ts, cnt))
