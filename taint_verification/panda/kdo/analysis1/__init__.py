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

from .mappings import ProcessMappings

analysis = dict()
memcpy_hit_ctr = 0
kasan_check_write_hit_ctr = 0


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

	panda.load_plugin("taint2", args={"opt": True, "no_tp": True})
	panda.load_plugin("osi", args={"disable-autoload": True})
	panda.load_plugin("osi_linux", args={
		"kconf_file": kernel.info_path, "kconf_group": "linux:1.0:64"
	})
	panda.load_plugin("callstack_instr")

	outfile = open('./kllvm_output1', "w+")

	pm = ProcessMappings(panda, ki)

	print(
		f'[analysis1] VMA walker offsets: '
		f'mm_mt={pm._MM_MT_OFFSET} ma_root={pm._MT_MA_ROOT_OFFSET} '
		f'mn_slot0={pm._MN_SLOT0_OFFSET} mn_slots={pm._MN_NUM_SLOTS} '
		f'mr64_pivot0={pm._MR64_PIVOT0_OFFSET} mr64_num_pivots={pm._MR64_NUM_PIVOTS} '
		f'mr64_slot={pm._MR64_SLOT_OFFSET} mr64_meta={pm._MR64_META_OFFSET} mr64_slots={pm._MR64_NUM_SLOTS} '
		f'ma64_pivot0={pm._MA64_PIVOT0_OFFSET} ma64_num_pivots={pm._MA64_NUM_PIVOTS} '
		f'ma64_slot={pm._MA64_SLOT_OFFSET} ma64_meta={pm._MA64_META_OFFSET} ma64_slots={pm._MA64_NUM_SLOTS} '
		f'vma_start={pm._VMA_VM_START} vma_end={pm._VMA_VM_END} vma_flags={pm._VMA_VM_FLAGS} vma_file={pm._VMA_VM_FILE} '
		f'task_mm={pm._TASK_MM} f_path_dentry={pm._F_PATH_DENTRY} d_iname={pm._D_INAME}'
	)

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
	sink_sym              = symbol_map.get('sink', None)
	sink_addr             = sink_sym.address if sink_sym else None
	handle_mm_fault_sym   = symbol_map.get('handle_mm_fault', None)
	handle_mm_fault_addr  = handle_mm_fault_sym.address if handle_mm_fault_sym else None

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
	# The OOB store gated by __kasan_check_write is at bitmap_ip_add+0x3bf; the
	# return address (immediate caller seen by callstack_instr) is +0x3c0.
	bitmap_ip_add_kasan_retaddr = bitmap_ip_add_addr + 0x3c0 if bitmap_ip_add_addr is not None else None

	print(f'__asan_memcpy addr:         {hex(asan_memcpy_addr)}')
	print(f'__kasan_check_write addr:   {hex(kasan_check_write_addr) if kasan_check_write_addr else "NOT FOUND"}')
	print(f'copy_to_urb addr:           {hex(copy_to_urb_addr) if copy_to_urb_addr is not None else "NOT FOUND"}')
	print(f'copy_to_urb memcpy retaddr: {hex(copy_to_urb_memcpy_retaddr) if copy_to_urb_memcpy_retaddr is not None else "NOT FOUND"}')
	print(f'bitmap_ip_add addr:         {hex(bitmap_ip_add_addr) if bitmap_ip_add_addr else "NOT FOUND"}')
	print(f'bitmap_ip_add kasan retaddr:{hex(bitmap_ip_add_kasan_retaddr) if bitmap_ip_add_kasan_retaddr else "NOT FOUND"}')
	print(f'panic addr:                 {hex(panic_addr)}')
	print(f'kdo_store_callback addr:    {hex(kdo_store_cb_addr) if kdo_store_cb_addr else "NOT FOUND"}')
	print(f'sink addr:                  {hex(sink_addr) if sink_addr else "NOT FOUND"}')
	print(f'handle_mm_fault addr:       {hex(handle_mm_fault_addr) if handle_mm_fault_addr else "NOT FOUND"}')

	def log(s):
		if enable_logging:
			print(s, file=outfile)

	label_nr = 1

	def enable_taint():
		if not panda.taint_enabled():
			panda.taint_enable()

	def taint_label_range(cpu, base, length, label_entry):
		"""Assign a fresh label to translatable bytes in `length` bytes starting
		at virtual address `base`. `label_entry` is stored in label_map under that
		label iff at least one byte was translated and tainted.
		Assumes taint is already enabled.
		Returns (label_or_none, untranslatable_bytes)."""
		nonlocal label_nr
		translated_paddrs = []
		untranslatable = 0
		for offset in range(length):
			taint_paddr = panda.virt_to_phys(cpu, base + offset)
			if taint_paddr == 0xFFFFFFFFFFFFFFFF:
				untranslatable += 1
				continue
			translated_paddrs.append(taint_paddr)
		if not translated_paddrs:
			return None, untranslatable
		label = label_nr
		label_nr += 1
		label_map[label] = label_entry
		for taint_paddr in translated_paddrs:
			panda.taint_label_ram(taint_paddr, label)
		return label, untranslatable

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

	PAGE_SIZE = 0x1000

	# cpu_index -> fault address recorded at handle_mm_fault entry.
	# Keyed by CPU index so that SMP replays (multiple vCPUs) don't clobber
	# each other; in practice kdo replays are single-CPU, but the guard is free.
	handle_mm_fault_pending = {}

	# Pages that on_ret has classified as heap/anon and queued for taint labelling.
	# on_ret fires from PANDA_CB_BEFORE_BLOCK_EXEC — the TB for the current
	# iteration is *about to execute*, so calling taint_enable() there would set
	# execute_llvm=1 before the TB is dispatched, crashing on assert(llvm_tc_ptr).
	# on_call fires from PANDA_CB_AFTER_BLOCK_EXEC — the TB has already finished,
	# so taint_enable() there is safe: tb_flush runs at the very next
	# panda_callbacks_before_find_fast(), and tb_find then produces an LLVM TB.
	# Each entry is (page_base, vma_snapshot) so on_call can do the taint work.
	zero_page_pending = []

	# Set to True by on_sys_mmap_return when a new mapping was created.
	# on_call drains this flag and refreshes pm — by that point the kernel has
	# fully committed the maple-tree rewrite and returned to user space, so the
	# tree is stable and readable.
	refresh_pending = False

	def on_ret(cpu, addr):
		"""Hook on handle_mm_fault return.

		When the kernel services a demand-paging fault for an anonymous heap/brk
		VMA on behalf of the repro process, the zero-initialised page is now
		physically backed and writable.  We assign one fresh taint label to every
		byte of that page so that bytes which are never explicitly written by the
		reproducer (i.e. they remain zero) are still tracked when they reach the
		sink.  Any subsequent explicit store via kdo_store_callback will overwrite
		this background label with a more specific one, which is the desired
		behaviour.
		"""
		if handle_mm_fault_addr is None or addr != handle_mm_fault_addr:
			return

		cpu_idx = cpu.cpu_index
		fault_addr = handle_mm_fault_pending.pop(cpu_idx, None)
		if fault_addr is None:
			# on_ret fired for handle_mm_fault but we never saw the matching
			# on_call — most likely the hook was registered after the call was
			# already in flight, or the fault was re-entered recursively.
			print(f'[analysis1] on_ret(handle_mm_fault): no pending entry for cpu{cpu_idx}, skipping')
			return

		page_base = fault_addr & ~(PAGE_SIZE - 1)
		print(f'[analysis1] on_ret(handle_mm_fault): cpu{cpu_idx} fault_addr=0x{fault_addr:x} page_base=0x{page_base:x}')

		# Classify the faulted page using the cached VMA list.
		# We only taint on-demand anonymous pages (heap / brk / plain anon).
		# Stack and file-backed pages are excluded.
		# Force a fresh walk of the maple tree so that a VMA created by this
		# very fault (e.g. first access to a new anonymous mapping) is visible.
		pm.refresh(cpu)
		containing_vma = None
		for mapping in pm.mappings:
			if mapping['base'] <= page_base < mapping['base'] + mapping['size']:
				containing_vma = mapping
				break

		if containing_vma is None:
			print(f'[analysis1] on_ret(handle_mm_fault): page 0x{page_base:x} not found in cached mappings ({len(pm.mappings)} entries) — skipping')
			return
		if containing_vma['name'] not in ('[heap]', '[anon]'):
			print(f'[analysis1] on_ret(handle_mm_fault): page 0x{page_base:x} in vma {containing_vma["name"]!r} — not heap/anon, skipping')
			return

		# Queue for taint labelling — do NOT call enable_taint() here.
		# on_ret fires from BEFORE_BLOCK_EXEC; the TB is still about to run.
		# enable_taint() sets execute_llvm=1 immediately, which would cause
		# assert(llvm_tc_ptr) on the same TB before tb_flush can clear the cache.
		# The work is drained by on_call which fires from AFTER_BLOCK_EXEC.
		zero_page_pending.append((page_base, dict(containing_vma)))
		print(f'[analysis1] on_ret(handle_mm_fault): queued page 0x{page_base:x} (vma {containing_vma["name"]}) for taint labelling')

	def on_call(cpu, addr):
		global memcpy_hit_ctr, kasan_check_write_hit_ctr, analysis
		nonlocal refresh_pending

		# Only care about calls from the reproducer process
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			return

		# Drain a deferred pm.refresh() requested by on_sys_mmap_return.
		# on_call fires from AFTER_BLOCK_EXEC — the first user-space TB after the
		# syscall return has already fully executed, so the kernel's maple-tree
		# rewrite is complete and the tree is stable to read.
		if refresh_pending:
			refresh_pending = False
			pm.refresh(cpu)

		# Drain any pages queued by on_ret.  on_call fires from AFTER_BLOCK_EXEC
		# so the current TB has already executed — safe to call enable_taint() and
		# issue taint_label_ram() calls here.
		while zero_page_pending:
			page_base, vma = zero_page_pending.pop(0)
			enable_taint()
			# Each byte of a zero page gets its own label so that individual
			# bytes that are never overwritten by kdo_store_callback can still
			# be identified at the sink.
			first_label = None
			last_label = None
			total_untranslatable = 0
			translated = 0
			for offset in range(PAGE_SIZE):
				virt_addr = page_base + offset
				label, untranslatable = taint_label_range(cpu, virt_addr, 1, {
					'virt_addr': hex(virt_addr),
					'backtrace': [],
					'type': 'zero_page',
				})
				total_untranslatable += untranslatable
				if label is None:
					continue
				translated += 1
				if first_label is None:
					first_label = label
				last_label = label
			if translated == 0:
				print(f'[analysis1] on_call drain: all {PAGE_SIZE} bytes untranslatable for page 0x{page_base:x}; no labels created')
			elif total_untranslatable:
				print(f'[analysis1] on_call drain: {total_untranslatable}/{PAGE_SIZE} bytes untranslatable for page 0x{page_base:x}; labels {first_label}..{last_label} ({translated} used)')
			else:
				print(f'[analysis1] on_call drain: labelled all {PAGE_SIZE} bytes of page 0x{page_base:x} (vma {vma["name"]} 0x{vma["base"]:x}+{vma["size"]}) with labels {first_label}..{last_label}')

		# handle_mm_fault(vma, address, flags, regs)
		# x86_64 SysV ABI: arg0=rdi (vma), arg1=rsi (address)
		if handle_mm_fault_addr is not None and addr == handle_mm_fault_addr:
			fault_addr = panda.arch.get_arg(cpu, 1)
			handle_mm_fault_pending[cpu.cpu_index] = fault_addr
			print(f'[analysis1] on_call(handle_mm_fault): cpu{cpu.cpu_index} address=0x{fault_addr:x}')
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
				log(f'kdo_store_cb id={store_id} ptr=0x{ptr:x} len={length} SKIP:non-positive-len')
				return

			store_end = ptr + length

			# Find which VMA contains ptr (start of range only, for diagnosis).
			containing = None
			for mapping in pm.mappings:
				if mapping['base'] <= ptr < mapping['base'] + mapping['size']:
					containing = mapping
					break

			is_h  = ProcessMappings.is_heap(containing) if containing else False
			fits  = (containing is not None and store_end <= containing['base'] + containing['size'])
			log(
				f'kdo_store_cb id={store_id} ptr=0x{ptr:x} len={length}'
				f' taint_enabled={panda.taint_enabled()}'
				+ (
					f' mapping={containing["name"]!r} 0x{containing["base"]:x}+0x{containing["size"]:x}'
					f' is_heap={is_h} fits={fits}'
					if containing else
					f' mapping=NONE (total={len(pm.mappings)})'
				)
				+ (
					' -> WILL_TAINT' if (is_h and fits) else ' -> SKIP'
				)
			)

			heap_mapping = None
			for mapping in pm.mappings:
				mapping_end = mapping['base'] + mapping['size']
				if ptr >= mapping['base'] and store_end <= mapping_end and ProcessMappings.is_heap(mapping):
					heap_mapping = mapping
					break

			if heap_mapping is None:
				# Diagnose why we skipped: find which mapping (if any) contains ptr
				# and report whether it was absent or present-but-not-heap.
				containing = None
				for mapping in pm.mappings:
					if mapping['base'] <= ptr < mapping['base'] + mapping['size']:
						containing = mapping
						break
				if containing is None:
					print(f'[analysis1] kdo_store_callback(id={store_id}, ptr=0x{ptr:x}, len={length}) — ptr not in any known mapping ({len(pm.mappings)} entries), skipping taint')
				else:
					print(f'[analysis1] kdo_store_callback(id={store_id}, ptr=0x{ptr:x}, len={length}) — ptr in mapping {containing["name"]!r} 0x{containing["base"]:x}+{containing["size"]} but is_heap=False, skipping taint')
				return

			print(f'[analysis1] kdo_store_callback(id={store_id}, ptr=0x{ptr:x}, len={length}) — in heap mapping 0x{heap_mapping["base"]:x}+{heap_mapping["size"]}, tainting')
	
			# All bytes from a single kdo_store_callback call share one label so
			# that the call site is the unit of taint granularity, not the byte.
			enable_taint()
			backtrace = [hex(a) for a in panda.callstack_callers(20, cpu)]
			call_label, untranslatable = taint_label_range(cpu, ptr, length, {
				'virt_addr': hex(ptr),
				'len': length,
				'backtrace': backtrace,
			})
			used_labels = length - untranslatable
			print(f'[analysis1]   tainted {length} bytes with label {call_label} ({used_labels}/{length} bytes translated)')
			return

		if sink_addr is not None and addr == sink_addr:
			# void sink(char *ptr, int len)
			# x86_64 SysV ABI: arg0=rdi (ptr), arg1=rsi (len, signed 32-bit)
			ptr    = panda.arch.get_arg(cpu, 0)
			length = panda.arch.get_arg(cpu, 1)
			length = length if length < (1 << 31) else length - (1 << 32)

			print(f'[analysis1] sink(ptr=0x{ptr:x}, len={length}) — checking taint')

			tainted_bytes = {}
			if length > 0:
				for offset in range(length):
					labels = get_taint_labels(cpu, ptr + offset)
					if labels:
						resolved = [label_map[l] for l in labels if l in label_map]
						tainted_bytes[offset] = resolved
						log(f'  taint: sink ptr[{offset}] @ 0x{ptr + offset:x} labels={labels} resolved={resolved}')

			if tainted_bytes:
				print(f'[analysis1] sink: tainted bytes: {tainted_bytes}')
			else:
				print(f'[analysis1] sink: no taint on sink bytes (ptr=0x{ptr:x}, len={length})')

			analysis['sink'] = {
				'ptr': hex(ptr),
				'len': length,
				'tainted_bytes': tainted_bytes,
			}
			panda.end_analysis()
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
				print(f'[analysis1] __asan_memcpy target hit complete — ending analysis')
				panda.end_analysis()
			return

		if kasan_check_write_addr is not None and addr == kasan_check_write_addr:
			kasan_check_write_hit_ctr += 1
			ptr  = panda.arch.get_arg(cpu, 0)
			size = panda.arch.get_arg(cpu, 1)
			is_target = (immediate_caller == bitmap_ip_add_kasan_retaddr)

			if is_target:
				print(f"[analysis1] *** TARGET HIT #{len(analysis.get('bitmap_ip_add_kasan_check_writes', [])) + 1} at kasan_check_write call #{kasan_check_write_hit_ctr} ***")

				# Inspect source value slots in bitmap_ip_add's stack frame.
				# rsp+0x10 holds the value about to be stored out-of-bounds;
				# taint on it confirms the OOB value traces back to user input.
				rsp = panda.arch.get_reg(cpu, 'rsp')
				tainted_src_bytes = {}
				for slot_name, slot_off in [('rsp+0x08', 0x08), ('rsp+0x10', 0x10)]:
					vaddr = rsp + slot_off
					try:
						raw = panda.virtual_memory_read(cpu, vaddr, 8)
						val = int.from_bytes(raw, 'little')
					except Exception as e:
						print(f'[analysis1]   {slot_name}=0x{vaddr:x} unreadable: {e}')
						continue
					paddr = panda.virt_to_phys(cpu, vaddr)
					if paddr == 0xFFFFFFFFFFFFFFFF:
						print(f'[analysis1]   {slot_name}=0x{vaddr:x} val=0x{val:x} not translatable')
						continue
					result = panda.taint_get_ram(paddr)
					labels = result.get_labels() if result is not None else set()
					resolved = [label_map[l] for l in labels if l in label_map]
					print(f'[analysis1]   src {slot_name}=0x{vaddr:x} val=0x{val:x} labels={labels} resolved={resolved}')
					if labels:
						tainted_src_bytes[slot_name] = {
							'vaddr': hex(vaddr),
							'val': hex(val),
							'labels': list(labels),
							'resolved': resolved,
						}

				analysis.setdefault('bitmap_ip_add_kasan_check_writes', []).append({
					'hit': kasan_check_write_hit_ctr,
					'backtrace': [hex(a) for a in callers],
					'ptr': hex(ptr),
					'size': size,
					'tainted_src_bytes': tainted_src_bytes,
				})

				if tainted_src_bytes:
					print(f"[analysis1] *** OOB TAINT CONFIRMED via source buffer: {len(tainted_src_bytes)} tainted slot(s) at kasan_check_write hit #{kasan_check_write_hit_ctr} ***")

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

		print(f"[analysis1] repro execve detected: {fname} — enabling on_call and on_ret hooks")
		panda.ppp("callstack_instr", "on_call")(on_call)
		panda.ppp("callstack_instr", "on_ret")(on_ret)
		panda.disable_ppp("on_sys_execve_enter")

	@panda.ppp("syscalls2", "on_sys_mmap_enter")
	def on_sys_mmap_enter(cpu, pc, addr_hint, length, prot, flags, fd, offset):
		if not pattern.search(panda.get_process_name(cpu)):
			return
		print(
			f'[analysis1] mmap enter: hint=0x{addr_hint:x} len=0x{length:x} '
			f'prot=0x{prot:x} flags=0x{flags:x} fd={fd} offset=0x{offset:x}'
		)

	@panda.ppp("syscalls2", "on_sys_mmap_return")
	def on_sys_mmap_return(cpu, pc, addr_hint, length, prot, flags, fd, offset):
		nonlocal refresh_pending
		if not pattern.search(panda.get_process_name(cpu)):
			return
		ret = panda.arch.get_retval(cpu)
		print(
			f'[analysis1] mmap return: addr=0x{ret:x} '
			f'(hint=0x{addr_hint:x} len=0x{length:x} '
			f'prot=0x{prot:x} flags=0x{flags:x} fd={fd} offset=0x{offset:x})'
		)
		# Don't refresh here — the kernel's maple-tree rewrite may not be fully
		# committed yet at the syscall-return boundary. Set a flag so on_call
		# refreshes on the next user-space instruction instead.
		refresh_pending = True

	@panda.ppp("syscalls2", "on_sys_brk_return")
	def on_sys_brk_return(cpu, pc, brk):
		nonlocal refresh_pending
		if not pattern.search(panda.get_process_name(cpu)):
			return
		ret = panda.arch.get_retval(cpu)
		print(f'[analysis1] brk return: new_brk=0x{ret:x} (requested=0x{brk:x})')
		# Same reasoning as mmap: defer the refresh to on_call.
		refresh_pending = True

	print(f'[analysis1] replay start: record={record}')
	try:
		panda.run_replay(record)
	except Exception:
		print("[analysis1] caught exception during replay")
		print(traceback.format_exc())

	outfile.close()
	print('[analysis1] replay done!')

	end = time.time()
	total_labels = label_nr - 1  # labels are 1-based
	print(f'[analysis1] time: {end - start:.1f}s')
	print(f'[analysis1] total __asan_memcpy calls in repro: {memcpy_hit_ctr}')
	print(f'[analysis1] copy_to_urb target hits: {len(analysis.get("copy_to_urb_memcpy_calls", []))}')
	print(f'[analysis1] total __kasan_check_write calls in repro: {kasan_check_write_hit_ctr}')
	print(f'[analysis1] bitmap_ip_add target hits: {len(analysis.get("bitmap_ip_add_kasan_check_writes", []))}')
	print(f'[analysis1] cached process mappings: {len(pm.mappings)}')
	print(f'[analysis1] total taint labels created: {total_labels}')

	analysis['memcpy_hit_ctr'] = memcpy_hit_ctr
	analysis['kasan_check_write_hit_ctr'] = kasan_check_write_hit_ctr
	analysis['replay_time'] = end - start
	analysis['total_taint_labels'] = total_labels
	analysis['process_mappings'] = len(pm.mappings)
	with open('./analysis1.json', 'w') as f:
		f.write(json.dumps(analysis, indent=2))


def replay(rootfs, kernel, enable_logging=True, record='record'):
	print("starting")
	rrr.replay(rootfs, kernel, record, __replay,
			   additional_args=[enable_logging])
