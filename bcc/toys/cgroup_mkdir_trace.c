// cgroup_mkdir_trace.c
// Author: Guochao
// Created on 23-01-2022

// Explore the power of BPF_STACK_TRACE

// Replace:
// - STACK_STORAGE_SIZE: default 16384

#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>

BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);
BPF_HASH(start_time, u64, u64);
BPF_PERF_OUTPUT(events);

struct data_t
{
    u64 time;
    u64 lat;
    int stackid;
};

// On function entry:
// 1. collect the stack_trace (kernel stack)
// 2. get time and store
KFUNC_PROBE(cgroup_mkdir)
{
    u64 pid = bpf_get_current_pid_tgid();
    int stackid = stack_traces.get_stackid(ctx, 0);

    u64 ts = bpf_ktime_get_ns();
    start_time.update(&pid, &ts);
    return 0;
}

// On function return:
// 1. get time and deduce
// 2. return the value
KRETFUNC_PROBE(cgroup_mkdir, int ret)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 time, delta, *tsp;
    struct data_t data = {};

    tsp = start_time.lookup(&pid);
    if (tsp != 0)
    {
        time = bpf_ktime_get_ns();
        delta = time - *tsp;
        data.time = time;
        data.lat = delta;
        data.stackid = stack_traces.get_stackid(ctx, 0);
        events.perf_submit(ctx, &data, sizeof(data));
        start_time.delete(&pid);
    }

    return 0;
}