#!/usr/bin/env python3

import argparse
import subprocess
import pathlib
import json
import os

def compile_c_repro(path, do_bug, outdir, clang, pass_plugin):
    repro_c = os.path.join(path, do_bug['id'], "repro.cprog")
    if not os.path.isfile(repro_c):
        raise BaseException(do_bug['id'])

    repro_out_path = os.path.join(outdir, do_bug['id'], 'repro')

    if pass_plugin:
        # Compile with clang and inject the kdo-store pass via -fpass-plugin.
        # -static keeps the same behaviour as the original gcc invocation.
        cmd = [
            clang, '-static', '-x', 'c', '-O0',
            f'-fpass-plugin={pass_plugin}',
            repro_c, '-o', repro_out_path,
        ]
    else:
        cmd = [clang, '-static', '-x', 'c', '-O0', repro_c, '-o', repro_out_path]

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode != 0:
        print("stdout:")
        print(result.stdout.decode(errors="replace"))
        print("stderr:")
        print(result.stderr.decode(errors="replace"))
        raise BaseException(do_bug['id'])

def main() -> None:
    opts = argparse.ArgumentParser(
            description='Update call_ids based on disassembling vmlinux')
    opts.add_argument('--reports-file', type=argparse.FileType('r'), required=True,
        help='reports json exported by extract-info.py')
    opts.add_argument('--path', type=pathlib.Path, required=True,
        help='Root folder containing <id>.c repro files')
    opts.add_argument('--outdir', type=pathlib.Path, required=True,
        help='Root folder containing <id>.c repro files')
    opts.add_argument('--clang', default='clang',
        help='Path to clang binary (default: clang from PATH)')
    opts.add_argument('--pass-plugin', default=None,
        help='Path to LLVMKdoStorePass.so; when set the pass is injected via -fpass-plugin')
    args = opts.parse_args()

    kdo_bugs = json.load(args.reports_file)

    for kdo_bug in kdo_bugs:
        compile_c_repro(args.path, kdo_bug, args.outdir, args.clang, args.pass_plugin)

if __name__ == '__main__':
    main()
