#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# biolatency    Summarize block device I/O latency as a histogram.
#       For Linux, uses BCC, eBPF.
#
# USAGE: biolatency [-h] [-T] [-Q] [-m] [-D] [interval] [count]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """examples:
    ./biolatency            # summarize block I/O latency as a histogram
    ./biolatency 1 10       # print 1 second summaries, 10 times
    ./biolatency -mT 1      # 1s summaries, milliseconds, and timestamps
    ./biolatency -Q         # include OS queued time in I/O time
    ./biolatency -D         # show each disk device separately
    ./biolatency -C         # show each blk cgroup separately
    ./biolatency -D -C      # show each combination of disk and blk cgroup separately
"""
parser = argparse.ArgumentParser(
    description="Summarize block device I/O latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-Q", "--queued", action="store_true",
    help="include OS queued time in I/O time")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-D", "--disks", action="store_true",
    help="print a histogram per disk device")
parser.add_argument("-C", "--cgroups", action="store_true",
    help="print a histogram per blk cgroup")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
args = parser.parse_args()
countdown = int(args.count)
debug = 1

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/cgroup-defs.h>
#include <linux/blk-cgroup.h>
#include <linux/kernfs.h>

typedef struct disk_io_cgrp {
    char disk[DISK_NAME_LEN];
    u64 io_cgrp;
} disk_io_cgrp_t;

typedef struct disk_io_cgrp_key {
    disk_io_cgrp_t dc;
    u64 slot;
} disk_io_cgrp_key_t;

typedef struct io_cgrp_key {
    u64 io_cgrp;
    u64 slot;
} io_cgrp_key_t;

typedef struct disk_key {
    char disk[DISK_NAME_LEN];
    u64 slot;
} disk_key_t;

typedef struct req_info {
    u64 io_cgrp;
    u64 ts;
}req_info_t;

REQUEST
STORAGE

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    SAVEREQ
    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    FETCHREQ_CALCDELTA
    FACTOR

    // store as histogram
    STORE

    start.delete(&req);
    return 0;
}
"""

# code substitutions
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"

if args.cgroups:
    bpf_text = bpf_text.replace('REQUEST',
            'BPF_HASH(start, struct request *, req_info_t);')
    bpf_text = bpf_text.replace('SAVEREQ', """
    req_info_t info = {};

    info.ts = bpf_ktime_get_ns();
    #ifdef CONFIG_BLK_CGROUP
    if (req->rl != 0) {
        info.io_cgrp = req->rl->blkg->blkcg->css.cgroup->kn->ino;
    } else {
        /*
         * blk-mq doesn't use req->rl, so now using the blkcg of
         * current task as a fallback
         */
         struct task_struct *task = NULL;

         task = (struct task_struct *)bpf_get_current_task();
         info.io_cgrp = task->cgroups->subsys[io_cgrp_id]->cgroup->kn->ino;
    }
    #endif
    start.update(&req, &info);
    """)
    bpf_text = bpf_text.replace('FETCHREQ_CALCDELTA',
    """
    req_info_t *info;
    u64 delta;

    info = start.lookup(&req);
    if (info == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - info->ts;
    """)
else:
    bpf_text = bpf_text.replace('REQUEST',
            'BPF_HASH(start, struct request *);')
    bpf_text = bpf_text.replace('SAVEREQ',
    """
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    """)
    bpf_text = bpf_text.replace('FETCHREQ_CALCDELTA',
    """
    u64 delta;
    u64 *tsp;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    """)

value = "disk"
bucket_fn = None
section_print_fn = None
bucket_sort_fn = None

def bucket_sort(buckets):
    buckets.sort()
    return buckets

if args.disks or args.cgroups:
    init_disk_key_fmt = "bpf_probe_read(&key{0}.disk, sizeof(key{0}.disk), req->rq_disk->disk_name); "
    init_cgroup_key_fmt = "key{0}.io_cgrp = info->io_cgrp;"

    if args.disks and args.cgroups:
        key_type = "disk_io_cgrp_key_t"
        init_key = init_disk_key_fmt.format(".dc") + \
            init_cgroup_key_fmt.format(".dc")
        value = "disk, cgroup"
        bucket_fn = lambda bucket: (bucket.disk, bucket.io_cgrp)
        section_print_fn = lambda bucket: "%s, %d" % (bucket[0], bucket[1])
        bucket_sort_fn = bucket_sort
    elif args.disks:
        key_type = "disk_key_t"
        init_key = init_disk_key_fmt.format("")
        value = "disk"
    else:
        key_type = "io_cgrp_key_t"
        init_key = init_cgroup_key_fmt.format("")
        value = "cgroup"
        section_print_fn = lambda bucket: "%d" % bucket

    bpf_text = bpf_text.replace('STORAGE',
        'BPF_HISTOGRAM(dist, %s);' % key_type)
    bpf_text = bpf_text.replace('STORE',
    """
    %s key = {.slot = bpf_log2l(delta)};
    %s
    dist.increment(key);""" % (key_type, init_key))
else:
    bpf_text = bpf_text.replace('STORAGE', 'BPF_HISTOGRAM(dist);')
    bpf_text = bpf_text.replace('STORE',
        'dist.increment(bpf_log2l(delta));')
if debug:
    print(bpf_text)

# load BPF program
b = BPF(text=bpf_text)
if args.queued:
    b.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
else:
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
    b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_completion",
    fn_name="trace_req_completion")

print("Tracing block device I/O... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    dist.print_log2_hist(label, value, bucket_fn=bucket_fn,
            section_print_fn=section_print_fn, bucket_sort_fn=bucket_sort_fn)
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
