#!/usr/bin/env python3

from pandare import Panda

import rrr
# Re-use the exact same Panda/QEMU config that kdo uses for recording
from kdo import conf

def update_config():
	rrr.update_config(conf)

import time
import json
import traceback
import re
import faulthandler
import tempfile

pattern = re.compile(r"\brepro$")

analysis = dict()
memcpy_hit_ctr = 0
kdo_label_nr = 1

# mmap tracking: maps mapped_addr -> {'len': int}
mmap_allocations = dict()
# pending mmap length from on_sys_mmap_enter, consumed by on_sys_mmap_return
_pending_mmap_len = None


def __replay(rootfs, kernel, record, _ignored_addresses, _func_map, symbol_map, enable_logging):
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

	panda.load_plugin("taint2", args={"opt": True})
	panda.load_plugin("osi", args={"disable-autoload": True})
	panda.load_plugin("osi_linux", args={
		"kconf_file": kernel.info_path, "kconf_group": "linux:1.0:64"
	})
	panda.load_plugin("callstack_instr")

	outfile = open('./kllvm_output1', "w+")

	# Maps label ID (int) -> {'virt_addr': hex str, 'backtrace': [hex str, ...]}
	label_map = {}

	asan_memcpy_addr = symbol_map.get('__asan_memcpy', None).address
	copy_to_urb_addr = (symbol_map.get('copy_to_urb.constprop.0', None)
	                    or symbol_map.get('copy_to_urb', None)).address
	panic_addr            = symbol_map.get('panic',             None).address
	kdo_store_cb_sym      = symbol_map.get('kdo_store_callback', None)
	kdo_store_cb_addr     = kdo_store_cb_sym.address if kdo_store_cb_sym else None

	# syscall() wrapper in the statically-linked repro binary.
	# The reproducer calls mmap via syscall(__NR_mmap, ...) so we intercept
	# the syscall() function entry, filter on __NR_mmap (rdi=9 on x86_64),
	# and record the return value on the matching return.
	__NR_mmap = 9
	syscall_sym  = symbol_map.get('syscall', None)
	syscall_addr = syscall_sym.address if syscall_sym else None
	print(f'syscall addr:               {hex(syscall_addr) if syscall_addr else "NOT FOUND"}')

	# The offending call is at copy_to_urb+0x308; the return address pushed on
	# the stack (what callstack_instr exposes as the immediate caller) is the
	# next instruction: copy_to_urb+0x309.
	copy_to_urb_memcpy_retaddr = copy_to_urb_addr + 0x309

	print(f'__asan_memcpy addr:         {hex(asan_memcpy_addr)}')
	print(f'copy_to_urb addr:           {hex(copy_to_urb_addr)}')
	print(f'copy_to_urb memcpy retaddr: {hex(copy_to_urb_memcpy_retaddr)}')
	print(f'panic addr:                 {hex(panic_addr)}')
	print(f'kdo_store_callback addr:    {hex(kdo_store_cb_addr) if kdo_store_cb_addr else "NOT FOUND"}')

	def log(s):
		if enable_logging:
			print(s, file=outfile)

	def enable_taint():
		if not panda.taint_enabled():
			panda.taint_enable()

	def get_taint_labels(cpu, addr):
		"""Return the set of taint labels on the byte at virtual address `addr`,
		or None if taint is not yet enabled or the byte is untainted."""
		if not panda.taint_enabled():
			return None
		taint_paddr = panda.virt_to_phys(cpu, addr)
		result = panda.taint_get_ram(taint_paddr)
		if result is None:
			return None
		return result.get_labels()

	def on_call(cpu, addr):
		global memcpy_hit_ctr, analysis, kdo_label_nr

		# Only care about calls from the reproducer process
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			return

		if kdo_store_cb_addr is not None and addr == kdo_store_cb_addr:
			# void kdo_store_callback(int id, void *ptr, int len)
			# x86_64 SysV ABI: arg0=rdi (id), arg1=rsi (ptr), arg2=rdx (len)
			store_id = panda.arch.get_arg(cpu, 0)
			ptr = panda.arch.get_arg(cpu, 1)
			length = panda.arch.get_arg(cpu, 2)
			# len is a signed 32-bit int — sign-extend from the register value
			length = length if length < (1 << 31) else length - (1 << 32)

			# Check whether [ptr, ptr+length) falls within any mmap'd region
			in_mmap = False
			for mmap_base, mmap_info in mmap_allocations.items():
				mmap_end = mmap_base + mmap_info['len']
				if ptr >= mmap_base and ptr + length <= mmap_end:
					in_mmap = True
					break

			if not in_mmap:
				# print(f'[analysis1] kdo_store_callback(id={store_id}, ptr=0x{ptr:x}, len={length}) — NOT in mmap range, skipping taint')
				return

			print(f'[analysis1] kdo_store_callback(id={store_id}, ptr=0x{ptr:x}, len={length}) — in mmap range 0x{mmap_base:x}+{mmap_info["len"]}, tainting')

			# Delete any existing taint on this range, then label each byte
			# with a fresh unique label.
			enable_taint()
			backtrace = [hex(a) for a in panda.callstack_callers(20, cpu)]
			for offset in range(length):
				virt_addr = ptr + offset
				taint_paddr = panda.virt_to_phys(cpu, virt_addr)
				panda.plugins['taint2'].taint2_delete_ram(taint_paddr)
				panda.taint_label_ram(taint_paddr, kdo_label_nr)
				label_map[kdo_label_nr] = {
					'virt_addr': hex(virt_addr),
					'backtrace': backtrace,
				}
				log(f'taint: label {kdo_label_nr} -> virt 0x{virt_addr:x} (phys 0x{taint_paddr:x})')
				kdo_label_nr += 1
			print(f'[analysis1]   tainted {length} bytes, labels {kdo_label_nr - length}..{kdo_label_nr - 1}')
			return

		if addr == panic_addr:
			analysis['memcpy_hit_ctr'] = memcpy_hit_ctr
			log('PANIC!')
			print(f"[analysis1] PANIC reached — memcpy_hit_ctr={memcpy_hit_ctr}, copy_to_urb hits={len(analysis.get('copy_to_urb_memcpy_calls', []))}")
			panda.end_analysis()
			return

		if addr != asan_memcpy_addr:
			return

		callers = list(panda.callstack_callers(20, cpu))
		immediate_caller = callers[0] if callers else None
		is_target = (immediate_caller == copy_to_urb_memcpy_retaddr)

		memcpy_hit_ctr += 1
		for a in callers:
			log(f'\t{hex(a)}')

		if is_target:
			print(f"[analysis1] *** TARGET HIT #{len(analysis.get('copy_to_urb_memcpy_calls', [])) + 1} at memcpy call #{memcpy_hit_ctr} ***")
			print(f"[analysis1] __asan_memcpy #{memcpy_hit_ctr} in '{pname}' from_copy_to_urb={is_target} caller={hex(immediate_caller) if immediate_caller else 'none'}")
			log(f'__asan_memcpy call #{memcpy_hit_ctr} (from_copy_to_urb={is_target}):')

			# void *__asan_memcpy(void *to, const void *from, uptr size)
			# x86_64 SysV ABI: arg0=rdi (to), arg1=rsi (from), arg2=rdx (size)
			from_ptr = panda.arch.get_arg(cpu, 1)
			size     = panda.arch.get_arg(cpu, 2)
			tainted_bytes = {}
			for offset in range(size):
				labels = get_taint_labels(cpu, from_ptr + offset)
				if labels:
					resolved = [label_map[l] for l in labels if l in label_map]
					tainted_bytes[offset] = resolved
					log(f'  taint: from[{offset}] @ 0x{from_ptr + offset:x} labels={labels} resolved={resolved}')
			if tainted_bytes:
				print(f'[analysis1]   tainted source bytes: {tainted_bytes}')
			else:
				print(f'[analysis1]   no taint on source bytes (from=0x{from_ptr:x}, size={size})')

			analysis.setdefault('copy_to_urb_memcpy_calls', []).append({
				'hit': memcpy_hit_ctr,
				'backtrace': [hex(a) for a in callers],
				'from': hex(from_ptr),
				'size': size,
				'tainted_bytes': tainted_bytes,
			})

	@panda.ppp("syscalls2", "on_sys_execve_enter")
	def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
		try:
			fname_bytes = panda.virtual_memory_read(cpu, fname_ptr, 256)
		except:
			print("[analysis1] warning: could not read execve fname")
			return
		fname = fname_bytes.split(b'\x00', 1)[0].decode('utf-8')

		if not pattern.search(fname):
			return

		print(f"[analysis1] repro execve detected: {fname} — enabling on_call hook")
		panda.ppp("callstack_instr", "on_call")(on_call)
		panda.disable_ppp("on_sys_execve_enter")

	# PPP signature: on_sys_mmap_enter(cpu, pc, addr, len, prot, flags, fd, pgoff)
	@panda.ppp("syscalls2", "on_sys_mmap_enter")
	def on_sys_mmap_enter(cpu, pc, hint_addr, length, prot, flags, fd, pgoff):
		global _pending_mmap_len
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			return
		print(f'[analysis1] mmap_enter: pname={pname!r} hint=0x{hint_addr:x} len={length}')
		_pending_mmap_len = length

	# PPP signature: on_sys_mmap_return(cpu, pc, addr, len, prot, flags, fd, pgoff)
	# retval is not passed — read rax directly.
	@panda.ppp("syscalls2", "on_sys_mmap_return")
	def on_sys_mmap_return(cpu, pc, hint_addr, length, prot, flags, fd, pgoff):
		global _pending_mmap_len, mmap_allocations
		pname = panda.get_process_name(cpu)
		retval = panda.arch.get_reg(cpu, "RAX")
		print(f'[analysis1] mmap_return: pname={pname!r} retval=0x{retval:x}')
		if not pattern.search(pname):
			if _pending_mmap_len is not None:
				_pending_mmap_len = None
			return
		if _pending_mmap_len is None:
			print(f'[analysis1] mmap_return: no pending len — skipping')
			return
		mapped_len = _pending_mmap_len
		_pending_mmap_len = None
		if retval >= (1 << 63):
			print(f'[analysis1] mmap_return: MAP_FAILED — skipping')
			return
		mmap_allocations[retval] = {'len': mapped_len}
		print(f'[analysis1] mmap_return: addr=0x{retval:x} len={mapped_len} — recorded')

	print(f'[analysis1] replay start: record={record}')
	try:
		panda.run_replay(record)
	except Exception:
		print("[analysis1] caught exception during replay")
		print(traceback.format_exc())

	outfile.close()
	print('[analysis1] replay done!')

	end = time.time()
	total_labels = kdo_label_nr - 1  # labels are 1-based
	print(f'[analysis1] time: {end - start:.1f}s')
	print(f'[analysis1] total __asan_memcpy calls in repro: {memcpy_hit_ctr}')
	print(f'[analysis1] copy_to_urb target hits: {len(analysis.get("copy_to_urb_memcpy_calls", []))}')
	print(f'[analysis1] total mmap regions tracked: {len(mmap_allocations)}')
	print(f'[analysis1] total taint labels created: {total_labels}')

	analysis['memcpy_hit_ctr'] = memcpy_hit_ctr
	analysis['replay_time'] = end - start
	analysis['total_taint_labels'] = total_labels
	analysis['mmap_regions'] = len(mmap_allocations)
	with open('./analysis1.json', 'w') as f:
		f.write(json.dumps(analysis, indent=2))


def replay(rootfs, kernel, enable_logging=True, record='record'):
	print("starting")
	rrr.replay(rootfs, kernel, record, __replay,
			   additional_args=[enable_logging])
