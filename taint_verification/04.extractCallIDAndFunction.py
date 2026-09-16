#!/usr/bin/env python3

import argparse
import pathlib
import json
import os
import re

KDO_PANIC_PATTERN = r'^.*KDO: .* hit \(id: (?P<func_offset>[^,]+), callid: (?P<call_id>[0-9]+)S\)$'
ADDR_PATTERN = r'^.*Write of size .* at addr (?P<addr>.*) by task.*$'

def process_record(record_txt) -> dict:
	with open(record_txt, 'r', encoding="ISO-8859-1") as f:
		kdo_lines = [line.rstrip() for line in f.readlines()]

	r = re.compile(KDO_PANIC_PATTERN)
	matches = [m.groupdict() for m in (r.match(line) for line in kdo_lines) if m]

	if len(matches) == 0:
		return {'err': 'no_crash'}

	if len(matches) > 1:
		raise BaseException(f"Multiple KDO hits in {record_txt}: {matches}")

	result = {'call_id': matches[0]['call_id'], 'site': matches[0]['func_offset']}

	# src/dst addrs — plain lines in the file
	r2 = re.compile(ADDR_PATTERN)
	addrs = [m.groupdict()['addr'] for m in (r2.match(line) for line in kdo_lines) if m]

	if len(addrs) == 0:
		result['err'] = 'no_dst'
	elif len(addrs) == 1:
		result['dst_addr'] = int(addrs[0], 16)
		result['err'] = 'no_src'
	else:
		result['dst_addr'] = int(addrs[0], 16)
		result['src_addr'] = int(addrs[1], 16)

	return result

def main() -> None:
	opts = argparse.ArgumentParser(
			description='Parse the repro logs and extract info into computer parsable format')
	opts.add_argument('--crashes', type=pathlib.Path, required=True,
		help='Path to crashes directory to parse')
	opts.add_argument('--infile', type=argparse.FileType('r'), required=True,
		help='Input JSON file with entries to augment (each must have an "id" field)')
	opts.add_argument('--outfile', type=argparse.FileType('w'), required=True,
		help='Output file')
	args = opts.parse_args()

	entries = json.load(args.infile)

	for entry in entries:
		if 'id' not in entry:
			raise SystemExit(f"Entry missing 'id' field: {entry}")

		record_txt = os.path.join(args.crashes, entry['id'], 'record.txt')
		if not os.path.isfile(record_txt):
			entry['err'] = 'no_crash'
			continue

		entry.update(process_record(record_txt))

	json.dump(entries, args.outfile, indent=4, sort_keys=True)

if __name__ == '__main__':
	main()
