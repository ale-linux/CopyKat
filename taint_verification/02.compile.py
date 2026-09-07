#!/usr/bin/env python3

import argparse
import subprocess
import pathlib
import json
import os

def merge_id_db(id_db):
    """If IDs.db.new exists, merge it into IDs.db (sorted, deduplicated) and remove it."""
    new_file = id_db + '.new'
    if not os.path.isfile(new_file):
        return

    # Read both files (IDs.db may not exist yet on first run).
    lines = set()
    for f in (new_file, id_db):
        if os.path.isfile(f):
            with open(f) as fh:
                lines.update(l.rstrip('\n') for l in fh if l.strip())

    with open(id_db, 'w') as fh:
        fh.write('\n'.join(sorted(lines)) + '\n')

    os.remove(new_file)
    print(f"[merge_id_db] merged {new_file} → {id_db} ({len(lines)} entries)")


def compile_c_repro(path, do_bug, outdir, clang, pass_plugin):
    repro_c = os.path.join(path, do_bug['id'], "repro.cprog")
    if not os.path.isfile(repro_c):
        raise BaseException(do_bug['id'])

    repro_out_path = os.path.join(outdir, do_bug['id'], 'repro')

    if pass_plugin:
        # Per-reproducer ID DB lives alongside the reproducer source.
        id_db = os.path.join(path, do_bug['id'], 'IDs.db')
        # Load the .so via -Xclang -load so that the -kdo-store-db CLI option
        # is registered (legacy PM path), then also inject via -fpass-plugin
        # for the new PM pipeline that actually runs the pass.
        cmd = [
            clang, '-static', '-g', '-x', 'c', '-O0',
            '-Xclang', '-load', '-Xclang', pass_plugin,
            f'-fpass-plugin={pass_plugin}',
            f'-mllvm=-kdo-store-db={id_db}',
            repro_c, '-o', repro_out_path,
        ]
    else:
        cmd = [clang, '-static', '-g', '-x', 'c', '-O0', repro_c, '-o', repro_out_path]

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.stdout:
        print("stdout:")
        print(result.stdout.decode(errors="replace"))
    if result.stderr:
        print("stderr:")
        print(result.stderr.decode(errors="replace"))

    if result.returncode != 0:
        raise BaseException(do_bug['id'])

    if pass_plugin:
        merge_id_db(id_db)

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
        help='Path to LLVMKdoStorePass.so; when set the pass is loaded via '
             '-Xclang -load and -fpass-plugin, and -kdo-store-db is set to '
             '<path>/<id>/IDs.db')
    args = opts.parse_args()

    kdo_bugs = json.load(args.reports_file)

    for kdo_bug in kdo_bugs:
        compile_c_repro(args.path, kdo_bug, args.outdir, args.clang, args.pass_plugin)

if __name__ == '__main__':
    main()
