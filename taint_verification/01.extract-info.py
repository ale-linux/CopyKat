#!/usr/bin/env python3

from typing import Optional

import argparse
import pathlib
import json
import os
import re

def process_crash(crash_dir) -> Optional[dict]:
	crash_id = os.path.split(crash_dir)[1].removesuffix(".old")
	return {'id': crash_id}

def main() -> None:
	opts = argparse.ArgumentParser(
			description='Scan crashes and extract one entry per crash into a computer parsable format')
	opts.add_argument('--crashes', type=pathlib.Path, required=True,
		help='Path to crashes directory to parse')
	opts.add_argument('--outfile', type=argparse.FileType('w'), required=True,
		help='Output file')
	args = opts.parse_args()

	bugs = []

	directory = os.fsencode(args.crashes)
	for file in os.listdir(directory):
		dirpath = f'{os.fsdecode(directory)}/{os.fsdecode(file)}'
		if os.path.isdir(dirpath):
			kdo_bug = process_crash(dirpath)
			if kdo_bug:
				bugs.append(kdo_bug)


	json.dump(bugs, args.outfile, indent=4, sort_keys=True)

if __name__ == '__main__':
	main()
