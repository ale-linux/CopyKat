#!/usr/bin/env python3

from typing import Optional

import argparse
import pathlib
import json
import os
import sys

KERNEL_FILE = "kernel"


def _read_or_prompt_kernel(crash_dir: str, kernels_path: str) -> str:
    """Return the kernel name for *crash_dir*.

    Reads it from <crash_dir>/kernel if present; otherwise prompts the user
    interactively, validates the answer against *kernels_path*, writes it back
    to that file for future runs, and returns the value.
    """
    kernel_path = os.path.join(crash_dir, KERNEL_FILE)
    if os.path.isfile(kernel_path):
        with open(kernel_path) as f:
            kernel = f.read().strip()
        if kernel:
            return kernel
        # File exists but is empty — treat as missing.

    crash_id = os.path.basename(crash_dir)
    print(f"\n[extract-info] No '{KERNEL_FILE}' file found in {crash_dir!r}")
    print(f"  crash id    : {crash_id}")
    if kernels_path:
        try:
            available = sorted(
                e for e in os.listdir(kernels_path)
                if os.path.isdir(os.path.join(kernels_path, e))
            )
            print(f"  available kernels under {kernels_path!r}: {available}")
        except OSError:
            pass

    while True:
        answer = input("  kernel name: ").strip()
        if not answer:
            print("  Please enter a non-empty kernel name.")
            continue
        if kernels_path:
            candidate = os.path.join(kernels_path, answer)
            if not os.path.isdir(candidate):
                print(f"  WARNING: {candidate!r} does not exist — are you sure? [y/N] ", end="")
                if input().strip().lower() != 'y':
                    continue
        break

    with open(kernel_path, "w") as f:
        f.write(answer + "\n")
    print(f"  Saved to {kernel_path!r} for future runs.")
    return answer


def process_crash(crash_dir: str, kernels_path: str) -> Optional[dict]:
    crash_id = os.path.basename(crash_dir)
    kernel = _read_or_prompt_kernel(crash_dir, kernels_path)
    return {'id': crash_id, 'kernel': kernel}


def main() -> None:
    opts = argparse.ArgumentParser(
            description='Scan crashes and extract one entry per crash into a computer parsable format')
    opts.add_argument('--crashes', type=pathlib.Path, required=True,
        help='Path to crashes directory to parse')
    opts.add_argument('--kernels', type=pathlib.Path, default=None,
        help='Path to the kernels directory (used to validate and list available kernel names)')
    opts.add_argument('--outfile', type=argparse.FileType('w'), required=True,
        help='Output file')
    args = opts.parse_args()

    kernels_path = str(args.kernels) if args.kernels else None

    if not sys.stdin.isatty():
        print("[extract-info] WARNING: stdin is not a tty — any crash directory "
              "missing a 'kernel' file will cause an error rather than a prompt.",
              file=sys.stderr)

    bugs = []

    directory = os.fsencode(args.crashes)
    for file in sorted(os.listdir(directory)):
        dirpath = os.path.join(os.fsdecode(directory), os.fsdecode(file))
        if os.path.isdir(dirpath):
            kdo_bug = process_crash(dirpath, kernels_path)
            if kdo_bug:
                bugs.append(kdo_bug)

    json.dump(bugs, args.outfile, indent=4, sort_keys=True)

if __name__ == '__main__':
    main()
