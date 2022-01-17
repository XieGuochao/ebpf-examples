#!/usr/bin/python3

# timing_mkdir.py
# Author: Guochao
# Created on 17-01-2022

# Print timing of mkdir

from bcc import BPF

program = r"""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d\n", delta / 1000000);  // export data through printk
        }
        last.delete(&key);
    }

    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("mkdir"), fn_name="do_trace")

start = 0
while 1:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    ms = ms.decode("utf8")
    print("At time %.2f s: multiple mkdir detected, last %s ms ago" % (ts, ms))
