#!/usr/bin/python3

# cgroup_mkdir_trace.py
# Author: Guochao Xie
# Created on 23-01-2022

# A demo to trace a kernel function and display the latency

from signal import SIGQUIT
from bcc import BPF
import argparse
from time import sleep, time

examples = """
    cgroup_mkdir_trace -i 5  # Interval 5 seconds
    cgroup_mkdir_trace --storage-size 16384  # Change the tracer storage size.
"""
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=examples)

parser.add_argument("-i", type=int, help="interval", default=5)
parser.add_argument("--storage-size", type=int,
                    help="the stack tracer's storage size", default=1000)

args = parser.parse_args()

with open("cgroup_mkdir_trace.c", "r") as f:
    src = f.read()
    src = src.replace("STACK_STORAGE_SIZE", str(args.storage_size))

b = BPF(text=src)
stack_traces = b.get_table("stack_traces")

print("start tracing:")

fmt = "%7d   %7d   %7d   %7d   %5d"
start = 0
latest_time = 0

lats = []
stackid = None


def print_value(cpu, data, size):
    global start, stackid, latest_time
    event = b["events"].event(data)
    if start == 0:
        start = event.time

    latest_time = event.time
    lats.append(event.lat)
    stackid = event.stackid


def lats_stats(lats, clear=False):
    if len(lats) == 0:
        return 0, 0, 0, 0
    sums = sum(lats)
    mins = min(lats)
    maxs = max(lats)
    avgs = sums // len(lats)
    count = len(lats)
    if clear:
        lats.clear()

    return mins//1000, maxs//1000, avgs//1000, count


finish = False
b["events"].open_perf_buffer(print_value)

start = time()
print("TIME(s)   MIN(us)   MAX(us)   AVG(us)  COUNT")
print(fmt % ((0,) + lats_stats(lats, clear=True)))

while True:
    interval_start = t = time()
    while t - interval_start <= args.i:
        try:
            b.perf_buffer_poll(200)
            t = time()
        except KeyboardInterrupt:
            finish = True
            break

    print(fmt % ((t - start,) + lats_stats(lats, clear=True)))

    if stackid is not None:
        print()
        for addr in stack_traces.walk(stackid):
            sym = b.ksym(addr, show_module=True, show_offset=True)
            print("\t%s" % sym.decode("utf8"))
        print()
        
    stackid = None

    if finish:
        exit(0)
