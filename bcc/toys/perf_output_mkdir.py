#!/usr/bin/python3

# perf_output_mkdir.py
# Author: Guochao
# Created on 20-01-2022

# Export the data using BPF_PERF_OUTPUT

from bcc import BPF

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/kernfs.h>
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(perf_events);

int hello(struct pt_args *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    perf_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b"cgroup_mkdir", fn_name="hello")

print("%-18s %-16s %-6s" % ("TIME(s)", "COMM", "PID"))

start = 0
def print_event(cpu, data, size):
    global start
    event = b["perf_events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d" % (time_s, event.comm.decode("utf8"), event.pid))

b["perf_events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()