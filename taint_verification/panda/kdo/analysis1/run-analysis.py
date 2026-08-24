#!/usr/bin/env -S python3 -u

import argparse
import json
import os
import re
import shutil
import sys

import rrr
from rrr import Stimulus, Rootfs, Kernel, config
from kdo import analysis1
import time

import multiprocessing as mp

import multiprocessing.pool

class NoDaemonProcess(multiprocessing.Process):
	@property
	def daemon(self):
		return False

	@daemon.setter
	def daemon(self, value):
		pass

class NoDaemonContext(type(multiprocessing.get_context())):
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
	os.chdir("/root/out")

	image_path = os.path.join(os.getcwd(), 'rootfs.qcow2')
	rootfs_path = os.path.join(os.getcwd(), 'rootfs/')
	busybox_path = os.path.join(os.getcwd(), 'busybox/')

	rootfs = Rootfs(
			None,
			image_path=image_path,
			rootfs_path=rootfs_path,
			busybox_path=busybox_path,
			avoid_create=(os.path.isfile(image_path)))
	kernel = Kernel('/root/kernel')

	print("starting on ", repro['id'])

	repro_id = repro['id']

	if not os.path.exists(repro_id):
		os.makedirs(repro_id)

	os.chdir(repro_id)

	# Point rootfs at the per-repro binary so rrr.replay() parses its symbols.
	# The binary lives in the share path under <repro_id>/repro (same layout
	# that rsync-repros uses to sync it into the VM).
	if share_path:
		repro_bin = os.path.join(share_path, repro_id, "repro")
		if os.path.isfile(repro_bin):
			rootfs.stimulus_debug_path = repro_bin
			print(f"[run-analysis] using repro binary: {repro_bin}")
		else:
			print(f"[run-analysis] warning: repro binary not found at {repro_bin}")

	if multi_shot:
		# A multi-shot run deliberately keeps going past the first confirmed
		# violation, which means it runs into this recording's desync point and is
		# killed by SIGABRT — rrr surfaces that as "Replay failed -6".  Every hit
		# has already been flushed to analysis1.json by then, so report it and
		# carry on rather than letting one expected abort take down the whole
		# pool.map batch.
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
			description='Run all the repros with panda syz-rrr')
	opts.add_argument('--record-file', type=argparse.FileType('r'), required=True,
			help='reports json exported by extract-info.py')
	opts.add_argument('--repro-id', nargs='*', required=False, help='repro id to reproduce')
	opts.add_argument('--npar', type=int, default=mp.cpu_count(), required=False, help='parallelism')
	opts.add_argument('--rerun', action='store_true', help='rerun the analysis only for the undone')
	opts.add_argument('--share-path', type=str, required=False,
			help='host share directory containing <repro_id>/repro binaries (for symbol parsing)')
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

	os.chdir("/root/out")

	repros = json.load(args.record_file)

	## # repro_id = "d73eeb2bc242f73eaaba9f0ef8118f82e93bb55b" # no taint
	## repro_id = "ac3bad7a701d9e0e4c6e3cce1f68392a5787dab7" # did not crash
	## # repro_id = "6e675f56f166258c81bc8343ed6b2207f05a00e6" # af_x25
	## # repro_id = "7857221bdd5e7ccc9978bf7dd186ac5157bcdb7b" # msg_msg
	## #repro_id = "c9f21bbd839ed1c76b88278ed7c77de8b7ac7c8f"
	## #repro_id = "428efbae6f77ce4c31be437177416ce2b15d7786" super slow

	#################
	# 3) get rootfs #
	#################

	print(f'Starting with parallelism {args.npar}')
	pool = NestablePool(args.npar)

	if args.repro_id:
		tmp = dict()
		for e in args.repro_id:
			tmp[e] = True
		torun = [r for r in repros if r['id'] in tmp]

		res = pool.map(doit, torun)

		print(res)

		return
	elif args.rerun:
		rr = []
		for r in repros:
			if 'err' in r: continue
			af = os.path.join("/root/out/", r["id"], "analysis1.json")
			if not os.path.isfile(af):
				rr.append(r)
				print(r['id'])
				continue

		res = pool.map(doit, rr)

		print(res)
	else:
		torun = [r for r in repros if "err" not in r]

		res = pool.map(doit, torun)

		print(res)

		return

if __name__ == '__main__':
	main()

