#!/usr/bin/env python3

from pandare import Panda

import rrr
# Re-use the exact same Panda/QEMU config that kdo uses for recording
from kdo import conf

def update_config():
	rrr.update_config(conf)

import struct
import time
import json
import traceback
import re
import faulthandler
import tempfile

pattern = re.compile(r"\brepro$")

analysis = dict()
memcpy_hit_ctr = 0
kasan_check_write_hit_ctr = 0
kdo_label_nr = 1

process_mappings = []


def _load_kernelinfo(path):
	"""Parse a kernelinfo.conf and return a flat dict of key -> int."""
	ki = {}
	with open(path) as f:
		for line in f:
			line = line.strip()
			if not line or line.startswith('[') or line.startswith('#'):
				continue
			if '=' not in line:
				continue
			key, _, val = line.partition('=')
			try:
				ki[key.strip()] = int(val.strip())
			except ValueError:
				pass  # strings like 'name = Linux' are ignored
	return ki


def __replay(rootfs, kernel, record, _ignored_addresses, _func_map, symbol_map, enable_logging):
	crashlogf = open(
		tempfile.NamedTemporaryFile(
			prefix="crash_info_", suffix=".log", dir=None, delete=False
		).name, "w"
	)
	faulthandler.enable(file=crashlogf)

	ki = _load_kernelinfo(kernel.info_path)
	print(f'[analysis1] kernelinfo loaded from {kernel.info_path}: {len(ki)} keys')

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
	kasan_check_write_sym = symbol_map.get('__kasan_check_write', None)
	kasan_check_write_addr = kasan_check_write_sym.address if kasan_check_write_sym else None
	copy_to_urb_sym = (symbol_map.get('copy_to_urb.constprop.0', None)
	                   or symbol_map.get('copy_to_urb', None))
	copy_to_urb_addr = copy_to_urb_sym.address if copy_to_urb_sym else None
	bitmap_ip_add_sym = symbol_map.get('bitmap_ip_add', None)
	bitmap_ip_add_addr = bitmap_ip_add_sym.address if bitmap_ip_add_sym else None
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
	copy_to_urb_memcpy_retaddr = copy_to_urb_addr + 0x309 if copy_to_urb_addr is not None else None
	bitmap_ip_add_kasan_retaddr = bitmap_ip_add_addr + 0x3c0 if bitmap_ip_add_addr is not None else None

	print(f'__asan_memcpy addr:         {hex(asan_memcpy_addr)}')
	print(f'__kasan_check_write addr:   {hex(kasan_check_write_addr) if kasan_check_write_addr else "NOT FOUND"}')
	print(f'copy_to_urb addr:           {hex(copy_to_urb_addr) if copy_to_urb_addr is not None else "NOT FOUND"}')
	print(f'copy_to_urb memcpy retaddr: {hex(copy_to_urb_memcpy_retaddr) if copy_to_urb_memcpy_retaddr is not None else "NOT FOUND"}')
	print(f'bitmap_ip_add addr:         {hex(bitmap_ip_add_addr) if bitmap_ip_add_addr else "NOT FOUND"}')
	print(f'bitmap_ip_add kasan retaddr:{hex(bitmap_ip_add_kasan_retaddr) if bitmap_ip_add_kasan_retaddr else "NOT FOUND"}')
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

	# ---------------------------------------------------------------------------
	# Maple-tree VMA walker for Linux 6.1+ kernels.
	#
	# All offsets are loaded from kernelinfo.conf (generated by GDB at startup)
	# so the walker works across kernel releases without any code changes.
	#
	# struct maple_node is 256 bytes and 256-byte aligned. The raw enode pointer
	# encodes the node address in bits 8+ and the node type in bits 3-6:
	#   node_addr = enode & ~0xFF
	#   node_type = (enode >> 3) & 0xF
	# enum maple_type: dense=0, leaf_64=1, range_64=2, arange_64=3
	# ---------------------------------------------------------------------------

	# Offsets from kernelinfo.conf (all sourced from GDB at kernelinfo generation time)
	_MM_MT_OFFSET    = ki['mm.mm_mt_offset']
	_MT_MA_ROOT_OFFSET = ki['maple.mt.ma_root_offset']

	_MR64_SLOT_OFFSET = ki['maple.mr64.slot0_offset']
	_MR64_META_OFFSET = ki['maple.mr64.meta_offset']
	_MR64_NUM_SLOTS   = ki['maple.mr64.num_slots']

	_MA64_SLOT_OFFSET = ki['maple.ma64.slot0_offset']
	_MA64_META_OFFSET = ki['maple.ma64.meta_offset']
	_MA64_NUM_SLOTS   = ki['maple.ma64.num_slots']

	# enode pointer tag bits — fixed by the maple tree ABI, not kernel-version-dependent
	_MAPLE_NODE_MASK       = 0xFF
	_MAPLE_NODE_TYPE_SHIFT = 3
	_MAPLE_NODE_TYPE_MASK  = 0xF

	# maple_type enum values — fixed by the kernel ABI
	_MTYPE_DENSE    = 0
	_MTYPE_LEAF_64  = 1
	_MTYPE_RANGE_64 = 2
	_MTYPE_ARANGE64 = 3

	# vm_area_struct offsets from kernelinfo.conf
	_VMA_VM_START = ki['vma.vm_start_offset']
	_VMA_VM_END   = ki['vma.vm_end_offset']
	_VMA_VM_FLAGS = ki['vma.vm_flags_offset']
	_VMA_VM_FILE  = ki['vma.vm_file_offset']

	# mm_struct offsets from kernelinfo.conf
	_MM_START_BRK   = ki['mm.start_brk_offset']
	_MM_BRK         = ki['mm.brk_offset']
	_MM_START_STACK = ki['mm.start_stack_offset']

	# task_struct and file/dentry offsets from kernelinfo.conf
	_TASK_MM       = ki['task.mm_offset']
	_F_PATH_DENTRY = ki['fs.f_path_dentry_offset']
	_D_INAME       = ki['path.d_iname_offset']

	print(
		f'[analysis1] VMA walker offsets: '
		f'mm_mt={_MM_MT_OFFSET} ma_root={_MT_MA_ROOT_OFFSET} '
		f'mr64_slot={_MR64_SLOT_OFFSET} mr64_meta={_MR64_META_OFFSET} mr64_slots={_MR64_NUM_SLOTS} '
		f'ma64_slot={_MA64_SLOT_OFFSET} ma64_meta={_MA64_META_OFFSET} ma64_slots={_MA64_NUM_SLOTS} '
		f'vma_start={_VMA_VM_START} vma_end={_VMA_VM_END} vma_flags={_VMA_VM_FLAGS} vma_file={_VMA_VM_FILE} '
		f'task_mm={_TASK_MM} f_path_dentry={_F_PATH_DENTRY} d_iname={_D_INAME}'
	)

	def _vmread64(cpu, addr):
		"""Read a little-endian u64 from guest virtual memory; return None on fault."""
		try:
			raw = panda.virtual_memory_read(cpu, addr, 8)
			return struct.unpack_from('<Q', raw)[0]
		except Exception:
			return None

	def _vmread8(cpu, addr):
		"""Read a single byte from guest virtual memory; return None on fault."""
		try:
			raw = panda.virtual_memory_read(cpu, addr, 1)
			return raw[0]
		except Exception:
			return None

	def _mt_node_addr(enode):
		"""Strip the type/flag tag bits from an encoded maple-tree node pointer."""
		return enode & ~_MAPLE_NODE_MASK

	def _mt_node_type(enode):
		"""Extract the maple_type enum value from an encoded node pointer."""
		return (enode >> _MAPLE_NODE_TYPE_SHIFT) & _MAPLE_NODE_TYPE_MASK

	def _mt_is_leaf(node_type):
		return node_type in (_MTYPE_DENSE, _MTYPE_LEAF_64)

	def _read_vma(cpu, vma_ptr, mm_ptr):
		"""
		Read a vm_area_struct and return a mapping dict.
		Returns None if the pointer looks invalid.
		"""
		vm_start = _vmread64(cpu, vma_ptr + _VMA_VM_START)
		vm_end   = _vmread64(cpu, vma_ptr + _VMA_VM_END)
		if vm_start is None or vm_end is None:
			return None
		if vm_end <= vm_start:
			return None

		vm_flags = _vmread64(cpu, vma_ptr + _VMA_VM_FLAGS) or 0
		vm_file  = _vmread64(cpu, vma_ptr + _VMA_VM_FILE)

		# Classify the region (mirrors osi_linux fill_osimodule logic)
		name = None
		if vm_file:
			# File-backed: resolve dentry name via offsets from kernelinfo.conf.
			dentry_ptr = _vmread64(cpu, vm_file + _F_PATH_DENTRY)
			if dentry_ptr:
				try:
					raw = panda.virtual_memory_read(cpu, dentry_ptr + _D_INAME, 32)
					name = raw.split(b'\x00', 1)[0].decode('utf-8', 'replace') or None
				except Exception:
					name = None
		else:
			# Anonymous: classify as heap / stack / unknown using mm fields.
			start_brk   = _vmread64(cpu, mm_ptr + _MM_START_BRK)
			brk         = _vmread64(cpu, mm_ptr + _MM_BRK)
			start_stack = _vmread64(cpu, mm_ptr + _MM_START_STACK)
			if start_brk is not None and brk is not None and vm_start <= start_brk and vm_end >= brk:
				name = '[heap]'
			elif start_stack is not None and vm_start <= start_stack <= vm_end:
				name = '[stack]'
			else:
				name = '[anon]'

		return {
			'base':   vm_start,
			'size':   vm_end - vm_start,
			'flags':  vm_flags,
			'name':   name,
			'file':   None,   # full path resolution not needed for heap-check
		}

	def _mt_walk_node(cpu, enode, mm_ptr, results, depth=0):
		"""
		Recursively walk a maple tree node, collecting leaf VMA pointers.
		enode is the raw encoded pointer as stored in a slot or ma_root.
		depth is a safety cap against corrupt/cyclic trees.
		"""
		if depth > 64:
			print('[analysis1] maple_walk: depth limit reached, aborting branch')
			return

		# A NULL or very-small enode means an empty slot — skip it.
		if enode is None or enode < 0x1000:
			return

		# From maple_tree.h: "If the tree contains a single entry at index 0,
		# it is usually stored in tree->ma_root."  A direct (non-node) root
		# entry has its bottom two bits clear (ends in 0b00).  Node pointers
		# always have at least one of bits 0-7 set (the type tag sits in bits
		# 3-6 and is never 0 for a real node except maple_dense=0, but
		# maple_dense nodes are 256B-aligned so bit 0 stays clear too).
		#
		# The reliable distinguisher from the kernel source is: a root value
		# stored as a direct entry has XA_ZERO_ENTRY (0x606) or ends in 0b00
		# or 0b01 or 0b11, whereas an enode pointer to an actual maple_node
		# has its bits 3-6 encoding the node type (1-3) and bits 0-2 encoding
		# the parent slot.  Since nodes are 256B-aligned, bits 0-7 of a
		# node pointer are always the tag word, and the type extracted by
		# (enode >> 3) & 0xF will be 1, 2, or 3.  If that value is 0 it is
		# a direct (leaf) root entry, not a node.
		node_type = _mt_node_type(enode)
		node_addr = _mt_node_addr(enode)

		if node_addr < 0x1000:
			return

		# type==0 with a real address: direct root entry (single VMA in tree).
		if node_type == _MTYPE_DENSE and depth == 0:
			# At root level, dense type tag means this IS the direct VMA pointer.
			entry = _read_vma(cpu, enode, mm_ptr)
			if entry:
				results.append(entry)
			return

		if node_type == _MTYPE_DENSE:
			# Dense node: all 31 slots are direct value pointers, no pivots.
			# Used very rarely; pivots are implied as consecutive integers.
			for i in range(31):
				slot_val = _vmread64(cpu, node_addr + 8 + i * 8)  # slots start at +8 (after parent)
				if slot_val and slot_val >= 0x1000:
					entry = _read_vma(cpu, slot_val, mm_ptr)
					if entry:
						results.append(entry)

		elif node_type in (_MTYPE_LEAF_64, _MTYPE_RANGE_64):
			meta_end = _vmread8(cpu, node_addr + _MR64_META_OFFSET)
			if meta_end is None:
				return
			# meta.end is the index of the last *used* slot (0-based).
			num_slots = min(meta_end + 1, _MR64_NUM_SLOTS)

			for i in range(num_slots):
				slot_val = _vmread64(cpu, node_addr + _MR64_SLOT_OFFSET + i * 8)
				if not slot_val or slot_val < 0x1000:
					continue
				if _mt_is_leaf(node_type):
					# Leaf: slot values are direct vm_area_struct pointers.
					entry = _read_vma(cpu, slot_val, mm_ptr)
					if entry:
						results.append(entry)
				else:
					# Internal node: slot values are child enodes.
					_mt_walk_node(cpu, slot_val, mm_ptr, results, depth + 1)

		elif node_type == _MTYPE_ARANGE64:
			meta_end = _vmread8(cpu, node_addr + _MA64_META_OFFSET)
			if meta_end is None:
				return
			num_slots = min(meta_end + 1, _MA64_NUM_SLOTS)

			for i in range(num_slots):
				slot_val = _vmread64(cpu, node_addr + _MA64_SLOT_OFFSET + i * 8)
				if not slot_val or slot_val < 0x1000:
					continue
				# arange_64 nodes are always internal (non-leaf).
				_mt_walk_node(cpu, slot_val, mm_ptr, results, depth + 1)

		else:
			print(f'[analysis1] maple_walk: unknown node type {node_type} at enode=0x{enode:x}')

	def refresh_process_mappings(cpu):
		global process_mappings

		# Get the current task_struct address via OSI (process identification
		# still works fine; only VMA traversal via osi_linux is broken).
		proc = panda.plugins['osi'].get_current_process(cpu)
		if proc == panda.ffi.NULL:
			process_mappings = []
			print('[analysis1] refresh: current process is NULL')
			return

		task_addr = int(proc.taskd)
		pname     = panda.ffi.string(proc.name).decode('utf-8', 'replace')

		mm_ptr = _vmread64(cpu, task_addr + _TASK_MM)
		if not mm_ptr:
			process_mappings = []
			print(f'[analysis1] refresh: mm is NULL for {pname!r}')
			return

		ma_root_addr = mm_ptr + _MM_MT_OFFSET + _MT_MA_ROOT_OFFSET
		ma_root = _vmread64(cpu, ma_root_addr)
		if not ma_root:
			process_mappings = []
			print(f'[analysis1] refresh: ma_root is NULL for {pname!r}')
			return

		print(f'[analysis1] refresh: task=0x{task_addr:x} mm=0x{mm_ptr:x} ma_root=0x{ma_root:x} proc={pname!r}')

		raw_vmas = []
		_mt_walk_node(cpu, ma_root, mm_ptr, raw_vmas)

		# Sort by base address (tree walk order is not guaranteed to be sorted).
		raw_vmas.sort(key=lambda v: v['base'])

		process_mappings = raw_vmas
		print(f'[analysis1] refreshed {len(process_mappings)} mappings for {pname!r}')
		for m in process_mappings:
			print(
				f'[analysis1]   0x{m["base"]:016x}-0x{m["base"]+m["size"]:016x} '
				f'flags=0x{m["flags"]:x} name={m["name"]!r}'
			)

	def is_heap_mapping(mapping):
		return mapping['name'] in ('[heap]', '[anon]', '[stack]')

	def on_call(cpu, addr):
		global memcpy_hit_ctr, kasan_check_write_hit_ctr, analysis, kdo_label_nr

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

			if length <= 0:
				return

			# print(f'[analysis1] kdo_store_callback(id={store_id}, ptr=0x{ptr:x}, len={length})')

			store_end = ptr + length
			heap_mapping = None
			for mapping in process_mappings:
				mapping_end = mapping['base'] + mapping['size']
				if ptr >= mapping['base'] and store_end <= mapping_end and is_heap_mapping(mapping):
					heap_mapping = mapping
					break

			if heap_mapping is None:
				return

			print(f'[analysis1] kdo_store_callback(id={store_id}, ptr=0x{ptr:x}, len={length}) — in heap mapping 0x{heap_mapping["base"]:x}+{heap_mapping["size"]}, tainting')

			# Label each byte with a fresh unique label if not already tainted.
			# (Deleting existing taint before re-labelling is disabled so that
			#  previously assigned labels are preserved.)
			enable_taint()
			backtrace = [hex(a) for a in panda.callstack_callers(20, cpu)]
			for offset in range(length):
				virt_addr = ptr + offset
				taint_paddr = panda.virt_to_phys(cpu, virt_addr)
				# Check whether this byte already carries a taint label; skip if so.
				existing = panda.taint_get_ram(taint_paddr)
				if existing is not None:
					existing_labels = existing.get_labels()  # consume iterator once
					if existing_labels:
						log(f'taint: skipping virt 0x{virt_addr:x} (phys 0x{taint_paddr:x}) — already labelled {existing_labels}')
						continue
				# panda.plugins['taint2'].taint2_delete_ram(taint_paddr)
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

		callers = list(panda.callstack_callers(20, cpu))
		immediate_caller = callers[0] if callers else None

		if addr == asan_memcpy_addr:
			is_target = (immediate_caller == copy_to_urb_memcpy_retaddr)
			memcpy_hit_ctr += 1

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
			return

		if kasan_check_write_addr is not None and addr == kasan_check_write_addr:
			is_target = (immediate_caller == bitmap_ip_add_kasan_retaddr)
			kasan_check_write_hit_ctr += 1

			if is_target:
				print(f"[analysis1] *** TARGET HIT #{len(analysis.get('bitmap_ip_add_kasan_check_writes', [])) + 1} at memcpy call #{kasan_check_write_hit_ctr} ***")
				print(f"[analysis1] __kasan_check_write #{kasan_check_write_hit_ctr} in '{pname}' from_copy_to_urb={is_target} caller={hex(immediate_caller) if immediate_caller else 'none'}")
				log(f'__kasan_check_write call #{kasan_check_write_hit_ctr} (from_copy_to_urb={is_target}):')

				ptr = panda.arch.get_arg(cpu, 0)
				size = panda.arch.get_arg(cpu, 1)
				tainted_bytes = {}
				for offset in range(size):
					labels = get_taint_labels(cpu, ptr + offset)
					if labels:
						resolved = [label_map[l] for l in labels if l in label_map]
						tainted_bytes[offset] = resolved
						log(f'  taint: from[{offset}] @ 0x{ptr + offset:x} labels={labels} resolved={resolved}')
				if tainted_bytes:
					print(f'[analysis1]   tainted write bytes: {tainted_bytes}')
				else:
					print(f'[analysis1]   no taint on write bytes (from=0x{ptr:x}, size={size})')

				analysis.setdefault('bitmap_ip_add_kasan_check_writes', []).append({
					'hit': kasan_check_write_hit_ctr,
					'backtrace': [hex(a) for a in callers],
					'from': hex(ptr),
					'size': size,
					'tainted_bytes': tainted_bytes,
				})
				return

		return

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

	@panda.ppp("syscalls2", "on_all_sys_return")
	def on_all_sys_return(cpu, pc, callno):
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			return
		refresh_process_mappings(cpu)

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
	print(f'[analysis1] total __kasan_check_write calls in repro: {kasan_check_write_hit_ctr}')
	print(f'[analysis1] bitmap_ip_add target hits: {len(analysis.get("bitmap_ip_add_kasan_check_writes", []))}')
	print(f'[analysis1] cached process mappings: {len(process_mappings)}')
	print(f'[analysis1] total taint labels created: {total_labels}')

	analysis['memcpy_hit_ctr'] = memcpy_hit_ctr
	analysis['kasan_check_write_hit_ctr'] = kasan_check_write_hit_ctr
	analysis['replay_time'] = end - start
	analysis['total_taint_labels'] = total_labels
	analysis['process_mappings'] = len(process_mappings)
	with open('./analysis1.json', 'w') as f:
		f.write(json.dumps(analysis, indent=2))


def replay(rootfs, kernel, enable_logging=True, record='record'):
	print("starting")
	rrr.replay(rootfs, kernel, record, __replay,
			   additional_args=[enable_logging])
