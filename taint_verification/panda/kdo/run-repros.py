#!/usr/bin/env -S python3 -u

import argparse
import json
import os
import sys

from rrr import Rootfs, Kernel, config
from kdo import RecordStatus
import kdo
import time
import pathlib


# Filesystem layout
# =================
#
# /root/kernel/<kernel_name>/          — pre-built kernel tree (read-only input)
#     vmlinux
#     vmlinux.btf
#     arch/x86/boot/bzImage
#
# /root/out/                           — working root (os.chdir here at startup, never leave
#                                        except into a per-kernel or repro subdirectory)
#     busybox/                         — single shared busybox source/build
#     rootfs/                          — single shared rootfs staging tree
#                                        (busybox symlinks + /init + helper scripts)
#                                        packed into each per-kernel qcow2 by virt-make-fs
#     <kernel_name>/                   — one directory per unique kernel string
#         rootfs.qcow2                 — per-kernel VM disk image (carries "root" snapshot)
#         kernelinfo.conf              — PANDA OSI offsets (written by Kernel.__init__
#                                        into cwd, so we chdir here before constructing)
#     <repro_id>/                      — per-repro recording output
#         record.txt
#         record-rr-nondet.log
#         …
#
# The rootfs/ staging tree is identical for all kernels; only the qcow2 image is
# per-kernel (because the "root" snapshot captures kernel-specific boot state).


KERNEL_BASE = "/root/kernel"
OUT_BASE    = "/root/out"

REQUIRED_KERNEL_FILES = [
    "vmlinux",
    "vmlinux.btf",
    os.path.join("arch", "x86", "boot", "bzImage"),
]


def _kernel_dir(kernel_name: str) -> str:
    return os.path.join(KERNEL_BASE, kernel_name)


def _out_kernel_dir(kernel_name: str) -> str:
    """Working directory for a specific kernel under /root/out."""
    return os.path.join(OUT_BASE, kernel_name)


def _validate_kernel(kernel_name: str) -> None:
    """Bail out early if any expected file is missing for *kernel_name*."""
    kdir = _kernel_dir(kernel_name)
    missing = [
        f for f in REQUIRED_KERNEL_FILES
        if not os.path.isfile(os.path.join(kdir, f))
    ]
    if missing:
        sys.exit(
            f"[run-repros] ERROR: kernel {kernel_name!r} is missing files "
            f"under {kdir}: {missing}"
        )


def _build_kernel_and_rootfs(kernel_name: str, shared_rootfs_path: str,
                              busybox_path: str) -> tuple:
    """
    Construct Kernel and Rootfs objects for *kernel_name*.

    *shared_rootfs_path* is the single staging tree under OUT_BASE that is
    shared across all kernels.  It is populated once (busybox symlinks + /init
    + helper scripts) and then packed by virt-make-fs into a per-kernel qcow2.

    Must be called while cwd == OUT_BASE (enforced by assertion inside).
    Chdirs into the per-kernel output directory so that kernelinfo.conf
    (written by Kernel.__init__ into cwd) lands in the right place, then
    restores cwd to OUT_BASE before returning.
    """
    assert os.path.realpath(os.getcwd()) == os.path.realpath(OUT_BASE), \
        f"_build_kernel_and_rootfs called from unexpected cwd: {os.getcwd()!r}"

    out_kdir = _out_kernel_dir(kernel_name)
    os.makedirs(out_kdir, exist_ok=True)

    # chdir into the per-kernel dir so kernelinfo.conf lands there.
    os.chdir(out_kdir)

    image_path = os.path.join(out_kdir, "rootfs.qcow2")

    # Write helper scripts into the shared staging tree before packing.
    kdo.setup_rootfs_scripts(shared_rootfs_path)

    kernel = Kernel(_kernel_dir(kernel_name))

    rootfs = Rootfs(
        None,
        image_path=image_path,
        rootfs_path=shared_rootfs_path,
        busybox_path=busybox_path,
        avoid_create=os.path.isfile(image_path),
    )

    # Restore working directory to OUT_BASE.
    os.chdir(OUT_BASE)
    assert os.path.realpath(os.getcwd()) == os.path.realpath(OUT_BASE)

    return kernel, rootfs


def main() -> None:
    opts = argparse.ArgumentParser(
            description='Run all the repros with panda syz-rrr')
    opts.add_argument('--reports-file', type=argparse.FileType('r'), required=True,
            help='reports json exported by extract-info.py')
    opts.add_argument('--path', type=pathlib.Path, required=True,
        help='Path to the reports')
    opts.add_argument('--outfile', type=argparse.FileType('w'), required=True,
        help='Output file')
    opts.add_argument('--share-path', type=pathlib.Path, required=True,
        help='Host directory to share with the guest via virtio-9p (mounted at /mnt/)')
    opts.add_argument('--skip-rsync', action='store_true', default=False,
        help='Skip the rsync step before recording (repros must already be present in the snapshot)')
    opts.add_argument('--repro', metavar='REPRO_ID', default=None,
        help='Record only this single repro ID instead of all')
    args = opts.parse_args()

    kdo.update_config(share_path=str(args.share_path))

    # Establish and verify the working root.  Everything that follows relies on
    # this as the stable base directory.
    os.chdir(OUT_BASE)
    assert os.path.realpath(os.getcwd()) == os.path.realpath(OUT_BASE)

    reports_json = json.load(args.reports_file)

    # -------------------------------------------------------------------------
    # Pre-flight: validate that every referenced kernel exists on disk before
    # we start any long-running recording work.
    # -------------------------------------------------------------------------
    unique_kernels = {report['kernel'] for report in reports_json}
    for kernel_name in sorted(unique_kernels):
        _validate_kernel(kernel_name)
    print(f"[run-repros] pre-flight OK — kernels: {sorted(unique_kernels)}")

    # -------------------------------------------------------------------------
    # Build one Kernel + Rootfs per unique kernel name.
    # busybox/ is shared across all kernels; it lives directly under OUT_BASE.
    # All Kernel objects are constructed here, while cwd == OUT_BASE, so that
    # kernelinfo.conf ends up in the per-kernel output directory and never
    # collides across kernels.
    # -------------------------------------------------------------------------
    busybox_path       = os.path.join(OUT_BASE, "busybox")
    shared_rootfs_path = os.path.join(OUT_BASE, "rootfs")

    kernel_map: dict = {}   # kernel_name -> Kernel
    rootfs_map: dict = {}   # kernel_name -> Rootfs

    for kernel_name in sorted(unique_kernels):
        print(f"[run-repros] initialising kernel/rootfs for {kernel_name!r} ...")
        kernel, rootfs = _build_kernel_and_rootfs(kernel_name, shared_rootfs_path, busybox_path)
        kernel_map[kernel_name] = kernel
        rootfs_map[kernel_name] = rootfs
        assert os.path.realpath(os.getcwd()) == os.path.realpath(OUT_BASE), \
            "cwd drifted after _build_kernel_and_rootfs"

    # -------------------------------------------------------------------------
    # Main recording loop.
    # -------------------------------------------------------------------------
    repros = [{"id": report['id'], "kernel": report['kernel']} for report in reports_json]

    if args.repro is not None:
        repros = [r for r in repros if r['id'] == args.repro]
        if not repros:
            sys.exit(f"[run-repros] ERROR: repro {args.repro!r} not found in reports file")

    record_results = []

    for repro in repros:
        # Always reset to OUT_BASE at the top of every iteration so that a
        # failure or exception in a previous iteration can never leave us in
        # an unexpected directory.
        os.chdir(OUT_BASE)
        assert os.path.realpath(os.getcwd()) == os.path.realpath(OUT_BASE)

        repro_id    = repro['id']
        kernel_name = repro['kernel']

        kernel = kernel_map[kernel_name]
        rootfs = rootfs_map[kernel_name]

        repro_out = os.path.join(OUT_BASE, repro_id)
        os.makedirs(repro_out, exist_ok=True)
        os.chdir(repro_out)

        start = time.time()
        status = kdo.record(kernel, rootfs, 3600*2, repro_id, skip_rsync=args.skip_rsync)
        end = time.time()
        print(f'time: {end - start}')
        repro['time'] = end - start

        if status != RecordStatus.CRASH:
            repro['err'] = status.value
        record_results.append(repro)
        print(json.dumps(repro, indent=2), file=sys.stderr)

    json.dump(record_results, args.outfile, indent=5, sort_keys=True)

if __name__ == '__main__':
    main()
