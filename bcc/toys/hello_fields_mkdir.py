#!/usr/bin/python3

# hello_fields_mkdir.py
# Author: Guochao
# Created on 17-01-2022

# Print hello world fields on each mkdir

from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("hello world\n");
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("mkdir"), fn_name="hello")

print("%-18s %-16s %-6s %4s %s" % ("TIME(s)", "COMM", "PID", "cpu", "MESSAGE"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %4d %s" % (ts, task, pid, cpu, msg))
