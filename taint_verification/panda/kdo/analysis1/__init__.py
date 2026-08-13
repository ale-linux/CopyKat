#!/usr/bin/env python3

from pandare import Panda

import rrr
# Re-use the exact same Panda/QEMU config that kdo uses for recording
from kdo import conf

import time
import json
import traceback
import re
import faulthandler
import tempfile

pattern = re.compile(r"repro-[a-z_]+$")

analysis = dict()
memcpy_hit_ctr = 0


def __replay(rootfs, kernel, record, symbol_map, enable_logging):
	crashlogf = open(
		tempfile.NamedTemporaryFile(
			prefix="crash_info_", suffix=".log", dir=None, delete=False
		).name, "w"
	)
	faulthandler.enable(file=crashlogf)

	start = time.time()
	panda = Panda(arch=conf["arch"], mem=conf["mem"],
				  expect_prompt=conf["expect_prompt"], qcow=rootfs.path,
				  extra_args=conf["extra_qemu_machine_args"],
				  os_version="linux-64-linux:1.0")

	panda.load_plugin("osi", args={"disable-autoload": True})
	panda.load_plugin("osi_linux", args={
		"kconf_file": kernel.info_path, "kconf_group": "linux:1.0:64"
	})
	panda.load_plugin("callstack_instr")

	outfile = open('./kllvm_output1', "w+")

	asan_memcpy_addr = symbol_map.get('__asan_memcpy', None).address
	copy_to_urb_addr = symbol_map.get('copy_to_urb',  None).address
	panic_addr       = symbol_map.get('panic',         None).address

	# The offending call is at copy_to_urb+0x308; the return address pushed on
	# the stack (what callstack_instr exposes as the immediate caller) is the
	# next instruction: copy_to_urb+0x309.
	copy_to_urb_memcpy_retaddr = copy_to_urb_addr + 0x309

	print(f'__asan_memcpy addr:         {hex(asan_memcpy_addr)}')
	print(f'copy_to_urb addr:           {hex(copy_to_urb_addr)}')
	print(f'copy_to_urb memcpy retaddr: {hex(copy_to_urb_memcpy_retaddr)}')
	print(f'panic addr:                 {hex(panic_addr)}')

	def log(s):
		if enable_logging:
			print(s, file=outfile)

	def on_call(cpu, addr):
		global memcpy_hit_ctr, analysis

		if addr == panic_addr:
			analysis['memcpy_hit_ctr'] = memcpy_hit_ctr
			log('PANIC!')
			print("Terminating analysis...")
			panda.end_analysis()
			return

		if addr != asan_memcpy_addr:
			return

		# Only care about calls from the reproducer process
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			return

		callers = list(panda.callstack_callers(20, cpu))
		immediate_caller = callers[0] if callers else None
		is_target = (immediate_caller == copy_to_urb_memcpy_retaddr)

		memcpy_hit_ctr += 1
		log(f'__asan_memcpy call #{memcpy_hit_ctr} (from_copy_to_urb={is_target}):')
		for a in callers:
			log(f'\t{hex(a)}')

		if is_target:
			analysis.setdefault('copy_to_urb_memcpy_calls', []).append({
				'hit': memcpy_hit_ctr,
				'backtrace': [hex(a) for a in callers],
			})

	@panda.ppp("syscalls2", "on_sys_execve_enter")
	def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
		try:
			fname_bytes = panda.virtual_memory_read(cpu, fname_ptr, 256)
		except:
			print("would break on execve...")
			return
		fname = fname_bytes.split(b'\x00', 1)[0].decode('utf-8')
		print(f"execve enter: {fname}")

		panda.ppp("callstack_instr", "on_call")(on_call)
		panda.disable_ppp("on_sys_execve_enter")

	print('replay start')
	try:
		panda.run_replay(record)
	except Exception:
		print("caught exception")
		print(traceback.format_exc())

	outfile.close()
	print('replay done!')

	end = time.time()
	print(f'time: {end - start}')
	print(f'total __asan_memcpy calls observed: {memcpy_hit_ctr}')

	global analysis
	analysis['memcpy_hit_ctr'] = memcpy_hit_ctr
	analysis['replay_time'] = end - start
	with open('./analysis1.json', 'w') as f:
		f.write(json.dumps(analysis, indent=2))


def replay(rootfs, kernel, symbol_map, enable_logging=True, record='record'):
	print("starting")
	rrr.replay(rootfs, kernel, record, __replay,
			   additional_args=[symbol_map, enable_logging])
