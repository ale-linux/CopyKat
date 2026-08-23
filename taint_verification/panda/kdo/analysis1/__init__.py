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
import bisect
import faulthandler
import tempfile

pattern = re.compile(r"\brepro$")

from .mappings import ProcessMappings

analysis = dict()
memcpy_hit_ctr = 0
kasan_check_write_hit_ctr = 0
kdo_label_nr = 1

# REMOVEME: debug dump state for kasan_check_write target hits
_dbg_dump_base = None   # first ptr seen (set on hit #1, never changes)
_dbg_dump_next = None   # one-past-the-last byte already written (advances each hit)


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


def __replay(rootfs, kernel, record, _ignored_addresses, func_map, symbol_map, enable_logging):
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

	PAGE_SIZE = 0x1000

	# cpu_index -> fault address recorded at handle_mm_fault entry.
	# Keyed by CPU index so that SMP replays (multiple vCPUs) don't clobber
	# each other; in practice kdo replays are single-CPU, but the guard is free.
	handle_mm_fault_pending = {}

	# Raw page_base values queued by on_ret for classification and taint labelling.
	# on_ret fires from PANDA_CB_BEFORE_BLOCK_EXEC — the TB for the current
	# iteration is *about to execute*.  Reading guest virtual memory there
	# (e.g. for a VMA walk) can hit MMIO-backed page-table entries, which causes
	# address_space_read_continue() to call RR_DO_RECORD_OR_REPLAY at the wrong
	# rr_guest_instr_count and diverge the replay log.
	# on_call fires from PANDA_CB_AFTER_BLOCK_EXEC — the TB has already finished,
	# so pm.refresh() and taint_enable() are both safe there.
	# The VMA lookup + heap/anon filter is therefore done in the on_call drain,
	# not here.
	zero_page_pending = []

	# Set to True by on_sys_mmap_return when a new mapping was created.
	# on_call drains this flag and refreshes pm — by that point the kernel has
	# fully committed the maple-tree rewrite and returned to user space, so the
	# tree is stable and readable.
	refresh_pending = False

	# ------------------------------------------------------------------
	# OOB destination taint probe
	#
	# Goal: read the taint labels on the bytes that the kernel writes out of
	# bounds, using the __kasan_check_write call as the signal.
	#
	# Why this is not a one-liner: __kasan_check_write fires BEFORE the store,
	# and the obvious place to look afterwards — cb_virt_mem_after_write — is
	# the one place where the answer is guaranteed to be wrong.  That callback
	# fires from inside the store helper (softmmu_template.h:470, in
	# helper_le_stq_mmu_panda), but taint2's shadow-memory update for the very
	# same store is emitted as SEPARATE instructions AFTER the helper call
	# returns (PandaTaintVisitor::insertTaintBulk — insertLogPop() puts the
	# memlog pops after the store's CallInst, then taint_copy goes after those).
	# So inside the write callback the shadow still holds the PRE-store state:
	# correct value, zero taint.
	#
	# The earliest safe read point is after_insn_exec, whose helper is emitted
	# right after disas_insn() finishes the instruction
	# (target/i386/translate.c:8552-8557), giving this order within a single
	# instruction:
	#
	#   call helper_le_stq_mmu_panda(...)  -> the store; write watcher fires
	#   call taint_memlog_pop / taint_copy -> taint2 updates shadow memory
	#   call helper_panda_after_insn_exec  -> our probe: taint is now visible
	#                                         and no later insn has executed
	#
	# Cost is the constraint that shapes the rest.  The kernel runs with
	# kasan.fault=report, so the full KASAN report (unwind + symbolisation +
	# printk) executes inside __kasan_check_write and again inside
	# __asan_store8, BEFORE the store.  A probe on every instruction would be
	# unusable.  after_insn_translate is a TRANSLATE-time gate, so restricting
	# it to the storing function's own pc range means the report path (which
	# lives in other functions) never gets a probe emitted at all and costs
	# nothing at execution time.  The write watcher cannot be pc-gated, so it is
	# armed late instead: the first probe firing proves control is back inside
	# the function with the report behind us.  on_call turns it back off for the
	# duration of any callee — notably __asan_store8 and its own report.
	#
	# Division of labour:
	#   __kasan_check_write  -> dst/size, and the pc range to instrument
	#   virt_mem_after_write -> dst-keyed: "a write landed, at pc X".  No taint.
	#   after_insn_exec      -> reads the taint, one instruction after the store
	# ------------------------------------------------------------------
	_oob = {
		'armed': False,
		'dst': None,          # destination ptr flagged by __kasan_check_write
		'size': 0,
		'paddrs': [],         # dst byte offset -> paddr, resolved at arm time
		'func_addr': None,    # entry pc of the function performing the store
		'lo': 0, 'hi': 0,     # gate pc range
		'watcher_on': False,
		'store_seen': False,  # a write overlapping dst has landed
		'store_pc': None,
		'store_val': None,
		'taint_read': False,  # the probe actually got to read the shadow
		'probe_fired': 0,
		'hit': None,
		'entry': None,        # analysis dict to fill in when we finish
	}

	# rrr runs plain `nm` (no -S), so Func carries no size.  func_map is keyed by
	# address, so the next symbol above a function's entry is the best available
	# upper bound for its extent.
	_sym_addrs = sorted(func_map.keys())

	def _function_extent(func_addr, ret_pc, fallback=50):
		"""(lo, hi) pc range to instrument: from `ret_pc` (where control resumes
		after the KASAN check) to the end of the function at `func_addr`.

		nm also reports data symbols, so an implausibly large extent is clamped
		back to the ret_pc + fallback window.  Over-wide is harmless — the range
		only has to contain the store and exclude other functions."""
		i = bisect.bisect_right(_sym_addrs, func_addr)
		hi = _sym_addrs[i] if i < len(_sym_addrs) else None
		if hi is None or hi - func_addr > 0x2000:
			hi = ret_pc + fallback
		# Never return less than the fallback window: a stray intra-function
		# symbol would otherwise put the store outside the gated range, which
		# degrades to a 'store_not_read' verdict instead of an answer.
		return ret_pc, max(hi, ret_pc + fallback)

	@panda.cb_virt_mem_after_write(name='oob_write_watcher', enabled=False)
	def oob_write_watcher(cpu, pc, addr, size, buf):
		"""The dst-keyed detector for the OOB store.

		Its ONLY job is to record that a write landed in [dst, dst+size) and at
		which pc.  It deliberately does NOT read taint — see the block comment
		above: at this point taint_copy for this very store has not run yet, so
		the shadow would report the pre-store state.  It also reads no guest
		memory; the written value comes from `buf`."""
		dst = _oob['dst']
		if dst is None or not _oob['armed']:
			return
		if addr + size <= dst or addr >= dst + _oob['size']:
			return
		# PANDA hands us (uint8_t *)&val where val is a uint64_t, so never read
		# more than 8 bytes out of it regardless of the access width.
		val = int.from_bytes(bytes(panda.ffi.buffer(buf, min(size, 8))), 'little')
		if not _oob['store_seen']:
			_oob['store_seen'] = True
			_oob['store_pc']   = pc
			_oob['store_val']  = val
			print(f'[analysis1]   oob watcher: store landed pc=0x{pc:x} addr=0x{addr:x} '
				  f'size={size} value=0x{val:x} (taint read deferred to probe)')
		else:
			print(f'[analysis1]   oob watcher: EXTRA write to dst pc=0x{pc:x} '
				  f'addr=0x{addr:x} size={size} value=0x{val:x}')

	def _set_oob_watcher(on):
		"""Enable/disable the write watcher.

		Legal to call from inside the probe: it is just plist->enabled on a
		different callback list than the one being iterated, and in LLVM mode
		(which taint2 forces) tcg-llvm always emits the _panda store helpers,
		which dispatch mem callbacks unconditionally — so it takes effect on the
		very next memory access with no retranslation."""
		if on == _oob['watcher_on']:
			return
		if on:
			# No-op on the LLVM path (panda_use_memcb is only consulted by the
			# TCG host backend) but needed if this ever runs without taint2.
			panda.enable_memcb()
			panda.enable_callback('oob_write_watcher')
		else:
			panda.disable_callback('oob_write_watcher')
		_oob['watcher_on'] = on

	@panda.cb_after_insn_translate(name='oob_probe_gate', enabled=False)
	def oob_probe_gate(cpu, pc):
		"""Translate-time gate.  Emitting the probe only for instructions inside
		the storing function is what keeps the KASAN reporting path free of
		instrumentation: those pcs live in other functions, answer False here,
		and therefore cost nothing however many times they execute."""
		return _oob['armed'] and _oob['lo'] <= pc < _oob['hi']

	@panda.cb_after_insn_exec(name='oob_probe', enabled=False)
	def oob_probe(cpu, pc):
		"""Fires after each instruction in the gated range.

		NB `pc` is the NEXT instruction's address — translate.c reassigns pc_ptr
		via disas_insn() before emitting the helper — so the instruction that
		just completed is at the previous pc."""
		if not _oob['armed']:
			return 0
		_oob['probe_fired'] += 1
		# First firing means control is back inside the flagged function, so the
		# KASAN report is behind us: now it is cheap to watch writes.
		if not _oob['watcher_on']:
			_set_oob_watcher(True)
		if _oob['store_seen'] and not _oob['taint_read']:
			_read_oob_taint(cpu, pc)
		return 0

	def _read_oob_taint(cpu, probe_pc):
		"""Read taint on the OOB destination.

		Touches shadow memory only: the physical addresses were resolved at arm
		time (from AFTER_BLOCK_EXEC, where guest page-table reads are safe) and
		the written value came from the watcher's buffer.  Nothing here reads
		guest memory from inside translated code — see the RR divergence warning
		on on_ret."""
		size      = _oob['size']
		dst       = _oob['dst']
		store_pc  = _oob['store_pc']

		# probe_pc is the pc AFTER the completed instruction, so this difference
		# is the store instruction's length.  If it is not a plausible length we
		# are not on the store's own instruction: translate.c suppresses the
		# helper for block-terminating instructions (&& !dc->is_jmp), meaning the
		# probe is firing a block late and another write could have intervened.
		delta    = probe_pc - store_pc if store_pc is not None else None
		adjacent = delta is not None and 0 < delta <= 15
		if not adjacent:
			print(f'[analysis1]   WARNING: probe pc=0x{probe_pc:x} is not adjacent to '
				  f'store pc=0x{store_pc:x} (delta={delta}) — the store may have ended its '
				  f'block and a later write could have clobbered dst; a negative result '
				  f'here is unproven')

		tainted_bytes  = {}
		untranslatable = 0
		if panda.taint_enabled():
			for off in range(size):
				paddr = _oob['paddrs'][off] if off < len(_oob['paddrs']) else None
				if paddr is None:
					untranslatable += 1
					continue
				result = panda.taint_get_ram(paddr)
				labels = result.get_labels() if result is not None else None
				if labels:
					resolved = [label_map[l] for l in labels if l in label_map]
					tainted_bytes[off] = {'labels': list(labels), 'resolved': resolved}
					log(f'  oob dst[{off}] @ 0x{dst + off:x} (pa 0x{paddr:x}) '
						f'labels={labels} resolved={resolved}')
		else:
			print('[analysis1]   WARNING: taint not enabled at probe time — cannot read taint')

		_oob['taint_read'] = True
		_finish_oob('store observed by watcher', tainted_bytes, untranslatable,
					probe_pc, adjacent)

	def _finish_oob(reason, tainted_bytes=None, untranslatable=0,
					probe_pc=None, adjacent=None):
		"""Record the outcome and disarm.

		Four distinguishable outcomes — the point of the whole exercise is that
		"the store never executed" is never reported as "no taint":
		  tainted              store landed, dst carries labels
		  untainted            store landed, no labels — a real negative
		  store_not_read       store landed but the probe never got to look
		  store_never_executed no write to dst was ever observed
		Only reads shadow state and flips callback flags, so it is safe to call
		from on_ret (BEFORE_BLOCK_EXEC) as well as from the probe."""
		if not _oob['armed']:
			return
		dst, size, hit = _oob['dst'], _oob['size'], _oob['hit']
		store_pc, store_val = _oob['store_pc'], _oob['store_val']

		if not _oob['store_seen']:
			outcome = 'store_never_executed'
			print(f'[analysis1] *** OOB PROBE INCONCLUSIVE (hit #{hit}): {reason} — no write '
				  f'to 0x{dst:x} was ever observed, so this is NOT a taint negative '
				  f'(probe fired {_oob["probe_fired"]}x) ***')
		elif not _oob['taint_read']:
			outcome = 'store_not_read'
			print(f'[analysis1] *** OOB PROBE INCONCLUSIVE (hit #{hit}): {reason} — store '
				  f'landed at pc=0x{store_pc:x} but the probe never read the shadow '
				  f'(probe fired {_oob["probe_fired"]}x) ***')
		elif tainted_bytes:
			outcome = 'tainted'
			print(f'[analysis1] *** OOB TAINT CONFIRMED (hit #{hit}): '
				  f'{len(tainted_bytes)}/{size} dst bytes tainted at 0x{dst:x}, '
				  f'store pc=0x{store_pc:x} value=0x{store_val:x} ***')
			for off, info in sorted(tainted_bytes.items()):
				print(f'[analysis1]     dst[{off}] labels={info["labels"]} '
					  f'resolved={info["resolved"]}')
		else:
			outcome = 'untainted'
			print(f'[analysis1] *** OOB WRITE NOT TAINTED (hit #{hit}): store pc=0x{store_pc:x} '
				  f'value=0x{store_val:x} landed at 0x{dst:x} but none of the {size} bytes '
				  f'carry taint ***')

		if untranslatable:
			print(f'[analysis1]   note: {untranslatable}/{size} dst bytes were not '
				  f'translatable at arm time')

		if _oob['entry'] is not None:
			_oob['entry']['oob_dst'] = {
				'outcome': outcome,
				'reason': reason,
				'store_pc': hex(store_pc) if store_pc is not None else None,
				'store_val': hex(store_val) if store_val is not None else None,
				'probe_pc': hex(probe_pc) if probe_pc is not None else None,
				'probe_adjacent': adjacent,
				'probe_firings': _oob['probe_fired'],
				'gate_range': [hex(_oob['lo']), hex(_oob['hi'])],
				'untranslatable_bytes': untranslatable,
				'tainted_bytes': tainted_bytes or {},
			}
		log(f'oob probe: dst=0x{dst:x} size={size} outcome={outcome} reason={reason}')

		_set_oob_watcher(False)
		panda.disable_callback('oob_probe')
		panda.disable_callback('oob_probe_gate')
		_oob.update({'armed': False, 'dst': None, 'entry': None})

	def _arm_oob_probe(cpu, dst, size, ret_pc, func_addr, hit, entry):
		"""Arm the destination-side probe for a flagged OOB write.

		Must be called from AFTER_BLOCK_EXEC (i.e. from on_call): the dst->paddr
		walk reads guest page tables, and flush_tb() needs a block boundary to be
		honoured at."""
		if size <= 0 or size > 64:
			print(f'[analysis1]   oob probe: implausible size={size} from '
				  f'__kasan_check_write, falling back to 8')
			size = 8

		# Resolve dst -> physical addresses HERE, not in the probe.  Doing the
		# page-table walk from inside translated code risks the
		# RR_DO_RECORD_OR_REPLAY divergence documented on on_ret below.
		paddrs = []
		for off in range(size):
			p = panda.virt_to_phys(cpu, dst + off)
			paddrs.append(None if p == 0xFFFFFFFFFFFFFFFF else p)

		lo, hi = _function_extent(func_addr, ret_pc)
		_oob.update({
			'armed': True,
			'dst': dst,
			'size': size,
			'paddrs': paddrs,
			'func_addr': func_addr,
			'lo': lo, 'hi': hi,
			'store_seen': False,
			'store_pc': None,
			'store_val': None,
			'taint_read': False,
			'probe_fired': 0,
			'hit': hit,
			'entry': entry,
		})

		panda.enable_callback('oob_probe_gate')
		panda.enable_callback('oob_probe')
		# The gate is consulted at TRANSLATE time, and panda_enable_callback does
		# not flush the TB cache — without this, blocks already translated carry
		# no probe and it would simply never fire.  The flush is honoured at the
		# next panda_callbacks_before_find_fast(); the `call __kasan_check_write`
		# we are sitting on (and the `call __asan_store8` after it) both end
		# blocks, so it lands well before the storing block is looked up.
		panda.flush_tb()
		print(f'[analysis1]   oob probe armed: dst=0x{dst:x} size={size} '
			  f'gate=[0x{lo:x},0x{hi:x}) (watcher stays off until the report is done)')

	def removeme_debug_dump(cpu, ptr):
		"""REMOVEME: dump the region [_dbg_dump_base, ptr) as 8-byte quads.

		On the first call ptr becomes the base; nothing is printed.
		On every subsequent call the bytes written so far (base..ptr-1,
		exclusive of the current store which hasn't happened yet) are shown.
		"""
		global _dbg_dump_base, _dbg_dump_next
		if _dbg_dump_base is None:
			_dbg_dump_base = ptr
			_dbg_dump_next = ptr
			return
		# Print everything from base up to (but not including) the current ptr.
		# ptr advances by 8 each hit, so the range [_dbg_dump_base, ptr) grows.
		start = _dbg_dump_base
		end   = ptr          # exclusive — this store hasn't happened yet
		if end <= start:
			_dbg_dump_next = ptr
			return
		print(f'[REMOVEME] dump 0x{start:x}..0x{end-1:x} ({(end-start)//8} quad(s)):')
		addr = start
		while addr < end:
			try:
				raw = panda.virtual_memory_read(cpu, addr, 8)
				val = int.from_bytes(raw, 'little')
				print(f'[REMOVEME]   0x{addr:016x}:\t0x{val:016x}')
			except Exception as e:
				print(f'[REMOVEME]   0x{addr:016x}:\t<unreadable: {e}>')
			addr += 8
		_dbg_dump_next = ptr

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

		IMPORTANT: do NOT call pm.refresh() or any guest virtual-memory read here.
		on_ret fires from PANDA_CB_BEFORE_BLOCK_EXEC.  Reading guest memory at
		that point can cause address_space_read_continue() to call
		RR_DO_RECORD_OR_REPLAY(RR_CALLSITE_READ_1) on an MMIO-backed page-table
		entry, writing an RR_INPUT_4 log entry at the wrong rr_guest_instr_count.
		During replay rr_prog_point_compare() then sees current > recorded and
		aborts with "Ahead of log / FOUND DISAGREEMENT".
		VMA classification is deferred to the on_call drain (AFTER_BLOCK_EXEC).
		"""
		# OOB probe terminal condition: the flagged function has returned.  If no
		# write to dst was ever observed then the store did not execute — a
		# distinct outcome from "the store executed and carried no taint".
		# Safe here despite the warning above: _finish_oob only reads shadow
		# state and flips callback flags, it touches no guest memory.
		if _oob['armed'] and addr == _oob['func_addr']:
			_finish_oob('flagged function returned')

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
		print(f'[analysis1] on_ret(handle_mm_fault): cpu{cpu_idx} fault_addr=0x{fault_addr:x} page_base=0x{page_base:x} — queued for classification')

		# Queue raw page_base only.  VMA lookup + heap/anon filter happen in
		# the on_call drain where guest memory reads are safe (AFTER_BLOCK_EXEC).
		zero_page_pending.append(page_base)

	def on_call(cpu, addr):
		global memcpy_hit_ctr, kasan_check_write_hit_ctr, analysis, kdo_label_nr
		nonlocal refresh_pending

		# Only care about calls from the reproducer process
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			return

		# OOB probe: any call out of the flagged function leaves the region we
		# care about — notably __asan_store8, which runs its own KASAN report.
		# Turn the write watcher off for the duration; the next probe firing back
		# inside the function turns it on again.  Without this the second report
		# runs with a Python callback on every guest write.
		if _oob['watcher_on']:
			_set_oob_watcher(False)

		# Drain a deferred pm.refresh() requested by on_sys_mmap_return.
		# on_call fires from AFTER_BLOCK_EXEC — the first user-space TB after the
		# syscall return has already fully executed, so the kernel's maple-tree
		# rewrite is complete and the tree is stable to read.
		if refresh_pending:
			refresh_pending = False
			pm.refresh(cpu)

		# Drain any pages queued by on_ret.  on_call fires from AFTER_BLOCK_EXEC
		# so the current TB has already executed — safe to call pm.refresh(),
		# enable_taint(), and issue taint_label_ram() calls here.
		if zero_page_pending:
			# One refresh covers all queued pages: they were all faulted in the
			# same BEFORE_BLOCK_EXEC→AFTER_BLOCK_EXEC window so the VMA list
			# hasn't changed between them.
			pm.refresh(cpu)

		while zero_page_pending:
			page_base = zero_page_pending.pop(0)

			# Classify the faulted page using the freshly refreshed VMA list.
			containing_vma = None
			for mapping in pm.mappings:
				if mapping['base'] <= page_base < mapping['base'] + mapping['size']:
					containing_vma = mapping
					break

			if containing_vma is None:
				print(f'[analysis1] on_call drain: page 0x{page_base:x} not found in mappings ({len(pm.mappings)} entries) — skipping')
				continue
			if containing_vma['name'] not in ('[heap]', '[anon]'):
				print(f'[analysis1] on_call drain: page 0x{page_base:x} in vma {containing_vma["name"]!r} — not heap/anon, skipping')
				continue

			enable_taint()
			first_label = kdo_label_nr
			print(f'[analysis1] on_call drain: zero-page labels starting at {first_label} for page 0x{page_base:x} (vma {containing_vma["name"]} 0x{containing_vma["base"]:x}+{containing_vma["size"]})')
			untranslatable = 0
			for offset in range(PAGE_SIZE):
				virt_addr   = page_base + offset
				taint_paddr = panda.virt_to_phys(cpu, virt_addr)
				if taint_paddr == 0xFFFFFFFFFFFFFFFF:
					untranslatable += 1
					continue
				label_map[kdo_label_nr] = {
					'virt_addr': hex(virt_addr),
					'backtrace': [],
					'type': 'zero_page',
				}
				panda.taint_label_ram(taint_paddr, kdo_label_nr)
				kdo_label_nr += 1
			last_label = kdo_label_nr - 1
			if untranslatable:
				print(f'[analysis1] on_call drain: {untranslatable}/{PAGE_SIZE} bytes untranslatable for page 0x{page_base:x}; labels {first_label}..{last_label}')
			else:
				print(f'[analysis1] on_call drain: labelled all {PAGE_SIZE} bytes of page 0x{page_base:x} with labels {first_label}..{last_label}')

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
			call_label = kdo_label_nr
			kdo_label_nr += 1
			label_map[call_label] = {
				'virt_addr': hex(ptr),
				'len': length,
				'backtrace': backtrace,
			}
			for offset in range(length):
				virt_addr = ptr + offset
				taint_paddr = panda.virt_to_phys(cpu, virt_addr)
				panda.taint_label_ram(taint_paddr, call_label)
			print(f'[analysis1]   tainted {length} bytes with label {call_label}')
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
			return

		if kasan_check_write_addr is not None and addr == kasan_check_write_addr:
			is_target = (immediate_caller == bitmap_ip_add_kasan_retaddr)
			kasan_check_write_hit_ctr += 1

			if is_target:
				print(f"[analysis1] *** TARGET HIT #{len(analysis.get('bitmap_ip_add_kasan_check_writes', [])) + 1} at kasan_check_write call #{kasan_check_write_hit_ctr} ***")
				print(f"[analysis1] __kasan_check_write #{kasan_check_write_hit_ctr} in '{pname}' from_bitmap_ip_add={is_target} caller={hex(immediate_caller) if immediate_caller else 'none'}")
	
				ptr  = panda.arch.get_arg(cpu, 0)
				size = panda.arch.get_arg(cpu, 1)
				removeme_debug_dump(cpu, ptr)
				log(f'__kasan_check_write call #{kasan_check_write_hit_ctr} (from_bitmap_ip_add={is_target}):')

				# Call site is bitmap_ip_add+0x3bb (retaddr +0x3c0).  Disassembly:
				#   +970  mov 0x18(%rsp),%rax   ← destination address (== ptr / arg0)
				#   +975  mov 0x10(%rsp),%rdx   ← value to be written
				#   +980  mov %rdx,(%rax)       ← the actual store
				# So rsp+0x10 holds the value; rsp+0x18 is the destination (already
				# captured in ptr above).  rsp+0x08 is unrelated to this call site.
				rsp = panda.arch.get_reg(cpu, 'rsp')
				value_slot = rsp + 0x10
				read_len = min(size, 8) if size > 0 else 8
				log(f'  write target=0x{ptr:x} size={size} value_slot=rsp+0x10=0x{value_slot:x} (store not yet executed)')
				tainted_src = {}
				try:
					raw = panda.virtual_memory_read(cpu, value_slot, read_len)
					val = int.from_bytes(raw, 'little')
				except Exception as e:
					log(f'  rsp+0x10=0x{value_slot:x} unreadable: {e}')
					val = None
				if val is not None:
					slot_labels = set()
					for byte_off in range(read_len):
						baddr = panda.virt_to_phys(cpu, value_slot + byte_off)
						if baddr == 0xFFFFFFFFFFFFFFFF:
							continue
						result = panda.taint_get_ram(baddr)
						if result is not None:
							slot_labels.update(result.get_labels())
					resolved = [label_map[l] for l in slot_labels if l in label_map]
					log(f'  rsp+0x10=0x{value_slot:x} val=0x{val:x} labels={slot_labels} resolved={resolved}')
					print(f'[analysis1]   write target=0x{ptr:x}  value=0x{val:x}  taint_labels={slot_labels}  resolved={resolved}')
					if slot_labels:
						tainted_src['rsp+0x10'] = {
							'val': hex(val),
							'labels': list(slot_labels),
							'resolved': resolved,
						}
				else:
					print(f'[analysis1]   write target=0x{ptr:x}  value=<unreadable> (rsp=0x{rsp:x})')
	
				if not tainted_src:
					print(f'[analysis1]   no taint on write value (rsp+0x10=0x{value_slot:x})')

				entry = {
					'hit': kasan_check_write_hit_ctr,
					'backtrace': [hex(a) for a in callers],
					'ptr': hex(ptr),
					'size': size,
					'tainted_src': tainted_src,
				}
				analysis.setdefault('bitmap_ip_add_kasan_check_writes', []).append(entry)

				# Source-side taint (above) only shows the value heading for the
				# store.  Arm the destination-side probe to confirm the taint on
				# the bytes actually written out of bounds.  immediate_caller is
				# the return address, i.e. where control resumes inside
				# bitmap_ip_add once the KASAN report is done.
				if _oob['armed']:
					print(f'[analysis1]   oob probe still armed from hit #{_oob["hit"]} — '
						  f'closing it out before re-arming')
					_finish_oob('superseded by a later kasan_check_write target hit')
				_arm_oob_probe(cpu, ptr, size, immediate_caller, bitmap_ip_add_addr,
							   kasan_check_write_hit_ctr, entry)
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
	total_labels = kdo_label_nr - 1  # labels are 1-based
	print(f'[analysis1] time: {end - start:.1f}s')
	print(f'[analysis1] total __asan_memcpy calls in repro: {memcpy_hit_ctr}')
	print(f'[analysis1] copy_to_urb target hits: {len(analysis.get("copy_to_urb_memcpy_calls", []))}')
	print(f'[analysis1] total __kasan_check_write calls in repro: {kasan_check_write_hit_ctr}')
	print(f'[analysis1] bitmap_ip_add target hits: {len(analysis.get("bitmap_ip_add_kasan_check_writes", []))}')
	_oob_outcomes = [e.get('oob_dst', {}).get('outcome', 'probe-never-finished')
					 for e in analysis.get('bitmap_ip_add_kasan_check_writes', [])]
	print(f'[analysis1] OOB destination probe outcomes per hit: {_oob_outcomes}')
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
