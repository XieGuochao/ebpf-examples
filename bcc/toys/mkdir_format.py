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
#include <linux/sched.h>

BPF_HASH(start, u32);
BPF_PERF_OUTPUT(events);

struct data_t {
    u64 ts;
    u64 delta;
    u32 ret;
    char comm[TASK_COMM_LEN];
    char name[100];
};

KFUNC_PROBE(cgroup_mkdir) {
    // args is from /sys/kernel/debug/tracing/events/cgroup/cgroup_mkdir/format
    // although we are not using here.

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    start.update(&pid, &ts);

    return 0;
}

KRETFUNC_PROBE(cgroup_mkdir, struct kernfs_node *parent_kn, const char *name, umode_t mode, int ret) {
    u64 *tsp, delta;
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t data = {};
    data.ts = ts;
    data.ret = ret;

    tsp = start.lookup(&pid);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        data.delta = delta;
        bpf_probe_read_kernel_str(data.name, 100, name);
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
        start.delete(&pid);
    }
    return 0;
}
"""

b = BPF(text=program)

print("Start tracing")

format="%6.2f %10d     %3d %-20s %s"
print("%6s %10s     %3s %-20s %s" % ("time", "lat(us)", "ret", "name", "command"))
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print(format % (time_s, event.delta // 100, event.ret, event.name.decode("utf8"), event.comm.decode("utf8")))

b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()