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
	args = opts.parse_args()

	kdo.update_config(share_path=str(args.share_path))

	os.chdir("/root/out")

	reports_json = json.load(args.reports_file)

	repros = [{"id": report['id']} for report in reports_json]

	image_path = os.path.join(os.getcwd(), 'rootfs.qcow2')
	rootfs_path = os.path.join(os.getcwd(), 'rootfs/')
	busybox_path = os.path.join(os.getcwd(), 'busybox/')

	kdo.setup_rootfs_scripts(rootfs_path)

	rootfs = Rootfs(
			None,
			image_path=image_path,
			rootfs_path=rootfs_path,
			busybox_path=busybox_path,
			avoid_create=(os.path.isfile(image_path)))
	kernel = Kernel('/root/kernel')

	record_results = []

	for repro in repros:
		if len(record_results) > 0:
			print(json.dumps(record_results[-1], indent=2), file=sys.stderr)

		os.chdir("/root/out")
		repro_id = repro['id']

		if not os.path.exists(repro_id):
			os.makedirs(repro_id)

		os.chdir(repro_id)

		start = time.time()
		status = kdo.record(kernel, rootfs, 3600*2, repro_id, skip_rsync=args.skip_rsync)
		end = time.time()
		print(f'time: {end - start}')
		repro['time'] = end - start

		if status != RecordStatus.CRASH:
			repro['err'] = status.value
		record_results.append(repro)

	json.dump(record_results, args.outfile, indent=5, sort_keys=True)

if __name__ == '__main__':
	main()

