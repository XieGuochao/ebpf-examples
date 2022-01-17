#!/usr/bin/python3

# hello_world_cgroup_mkdir.py
# Author: Guochao
# Created on 17-01-2022

# Print hello world on each cgroup mkdir

from bcc import BPF

program = r"""
int kprobe__cgroup_mkdir(void *ctx) {
    bpf_trace_printk("hello world\n");
    return 0;
}
"""

BPF(text=program).trace_print()
