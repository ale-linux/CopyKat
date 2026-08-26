#!/usr/bin/env -S python3 -u

import argparse
import json
import os
import sys

import rrr
from rrr import Rootfs, Kernel
from kdo import analysis1
import time

import multiprocessing as mp
import multiprocessing.pool


# Filesystem layout (produced by run-repros.py, consumed here):
#
#   /root/kernel/<kernel_name>/      — pre-built kernel tree (read-only)
#   /root/out/
#       rootfs/                      — shared rootfs staging tree
#       busybox/                     — shared busybox build
#       <kernel_name>/
#           rootfs.qcow2             — snapshotted VM disk image
#           kernelinfo.conf          — PANDA OSI offsets
#       <repro_id>/
#           record-rr-nondet.log     — recording to replay
#           record-rr-snp            — recording snapshot
#           analysis1.json           — output written here

KERNEL_BASE = "/root/kernel"
OUT_BASE    = "/root/out"


class NoDaemonProcess(mp.Process):
    @property
    def daemon(self):
        return False

    @daemon.setter
    def daemon(self, value):
        pass

class NoDaemonContext(type(mp.get_context())):
    Process = NoDaemonProcess

# We sub-class multiprocessing.pool.Pool instead of multiprocessing.Pool
# because the latter is only a wrapper function, not a proper class.
class NestablePool(multiprocessing.pool.Pool):
    def __init__(self, *args, **kwargs):
        kwargs['context'] = NoDaemonContext()
        super(NestablePool, self).__init__(*args, **kwargs)


share_path = None
multi_shot = False


def doit(repro):
    repro_id    = repro['id']
    kernel_name = repro['kernel']
    out_kdir    = os.path.join(OUT_BASE, kernel_name)
    repro_out   = os.path.join(OUT_BASE, repro_id)

    print(f"[run-analysis] starting {repro_id!r} (kernel={kernel_name!r})")

    # Kernel.__init__ writes kernelinfo.conf into os.getcwd(), so we must be
    # in the per-kernel output dir when constructing it.  All kernel/btf files
    # already exist (run-repros.py built them), so the constructor only sets
    # attributes — no build work happens.
    os.chdir(out_kdir)
    kernel = Kernel(os.path.join(KERNEL_BASE, kernel_name))

    image_path   = os.path.join(out_kdir, "rootfs.qcow2")
    rootfs = Rootfs(
        None,
        image_path=image_path,
        rootfs_path=os.path.join(OUT_BASE, "rootfs"),
        busybox_path=os.path.join(OUT_BASE, "busybox"),
        avoid_create=True,
    )

    # Point rootfs at the per-repro binary so rrr.replay() parses its symbols.
    if share_path:
        repro_bin = os.path.join(share_path, repro_id, "repro")
        if os.path.isfile(repro_bin):
            rootfs.stimulus_debug_path = repro_bin
            print(f"[run-analysis] using repro binary: {repro_bin}")
        else:
            print(f"[run-analysis] warning: repro binary not found at {repro_bin}")

    # Recording files live in the repro output dir; replay must run from there.
    os.chdir(repro_out)

    if multi_shot:
        # A multi-shot run deliberately keeps going past the first confirmed
        # violation, which means it runs into this recording's desync point and
        # is killed by SIGABRT — rrr surfaces that as "Replay failed -6".
        # Every hit has already been flushed to analysis1.json by then, so
        # report it and carry on rather than letting one expected abort take
        # down the whole pool.map batch.
        try:
            analysis1.replay(rootfs, kernel, stop_on_first_violation=False)
        except Exception as e:
            print(f"[run-analysis] {repro_id}: replay ended with {e!r} — expected "
                  f"in --multi-shot; results already written to analysis1.json")
            return 'aborted-after-collection'
    else:
        analysis1.replay(rootfs, kernel)

    return True


def main() -> None:
    opts = argparse.ArgumentParser(
            description='Run analysis1 replay over recordings from run-repros.py')
    opts.add_argument('--record-file', type=argparse.FileType('r'), required=True,
            help='JSON output from run-repros.py (contains id + kernel per entry)')
    opts.add_argument('--repro-id', nargs='*', required=False,
            help='only run these specific repro ids')
    opts.add_argument('--npar', type=int, default=mp.cpu_count(), required=False,
            help='parallelism (default: cpu count)')
    opts.add_argument('--rerun', action='store_true',
            help='only run entries whose analysis1.json is missing')
    opts.add_argument('--share-path', type=str, required=False,
            help='host share directory containing <repro_id>/repro binaries '
                 '(for symbol parsing)')
    opts.add_argument('--multi-shot', action='store_true',
            help='collect every OOB violation instead of stopping at the first '
                 'confirmed one; analysis1.json is rewritten after each hit')
    args = opts.parse_args()

    global share_path, multi_shot
    share_path = args.share_path
    multi_shot = args.multi_shot
    if multi_shot:
        print('[run-analysis] --multi-shot: collecting all violations')

    analysis1.update_config()

    os.chdir(OUT_BASE)
    assert os.path.realpath(os.getcwd()) == os.path.realpath(OUT_BASE)

    repros = json.load(args.record_file)

    # Only replay entries that actually crashed (no 'err' key).
    crashed = [r for r in repros if 'err' not in r]

    if args.repro_id:
        wanted = set(args.repro_id)
        torun = [r for r in crashed if r['id'] in wanted]
    elif args.rerun:
        torun = [
            r for r in crashed
            if not os.path.isfile(os.path.join(OUT_BASE, r['id'], 'analysis1.json'))
        ]
        for r in torun:
            print(f"[run-analysis] queued (missing analysis1.json): {r['id']}")
    else:
        torun = crashed

    print(f"[run-analysis] {len(torun)} repro(s) to analyse (parallelism={args.npar})")

    pool = NestablePool(args.npar)
    res = pool.map(doit, torun)
    print(res)


if __name__ == '__main__':
    main()
