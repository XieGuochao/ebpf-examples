#!/usr/bin/python3

# mkdir_format.py
# Author: Guochao
# Created on 20-01-2022

# Print each time of cgroup mkdir
# Reformat to use TRACEPOINT_PROBE

from bcc import BPF

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/kernfs.h>

BPF_HASH(start, u32);
BPF_PERF_OUTPUT(events);

struct data_t {
    u64 ts;
    u64 delta;
};

TRACEPOINT_PROBE(cgroup, cgroup_mkdir) {
    // args is from /sys/kernel/debug/tracing/events/cgroup/cgroup_mkdir/format
    // although we are not using here.

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    start.update(&pid, &ts);

    return 0;
}

int kretprobe__cgroup_mkdir(struct pt_regs *ctx) {
    u64 *tsp, delta;
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t data = {};
    data.ts = ts;

    tsp = start.lookup(&pid);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        data.delta = delta;
        events.perf_submit(ctx, &data, sizeof(data));
        start.delete(&pid);
    }
    return 0;
}
"""

b = BPF(text=program)

print("Start tracing")


start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("At time %.2f s: %10d us" % (time_s, event.delta // 100))

b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()