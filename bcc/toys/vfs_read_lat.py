#!/usr/bin/python3

# vfs_read_lat.py
# Author: Guochao
# Created on 20-01-2022

# Combination of histogram and latency tracing

from asyncio import events
from bcc import BPF
from time import sleep

b = BPF(src_file="vfs_read_lat.c")
b.attach_kprobe(event=b"vfs_read", fn_name="do_entry")
b.attach_kretprobe(event=b"vfs_read", fn_name="do_return")

interval = 3

print("Hit Ctrl-C to end.")

do_exit = 0
while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass; do_exit = 1
    
    print()
    b["dist"].print_log2_hist("usecs")
    b["dist"].clear()
    if do_exit:
        exit()
