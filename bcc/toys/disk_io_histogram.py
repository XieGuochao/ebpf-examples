#!/usr/bin/python3

# disk_io_histogram.py
# Author: Guochao
# Created on 20-01-2022

# Use the BPF_HISTOGRAM

from bcc import BPF
from time import sleep

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req)
{
    dist.increment(bpf_log2l(req->__data_len / 1024));
    return 0;
}
"""

b = BPF(text=program)

print("Hit Ctrl-C to end.")

try:
    sleep(100)
except KeyboardInterrupt:
    print()

b["dist"].print_log2_hist("kbytes")