#!/usr/bin/env python3
"""analysis1 — is the data a kernel OOB write puts out of bounds attacker-tainted?

WHAT THIS ANSWERS
-----------------
kdo records a syzkaller reproducer running against a KASAN kernel.  The report
names a *faulting function + offset* — the return address of the KASAN helper
that noticed the access.  So the machine code looks like:

    call  <kasan helper>      # the check FAILS here; kasan_report() runs here
    insn                      # <-- the address the KASAN report prints
    ...
    <the OOB store>           # the out-of-bounds write actually happens HERE

The store has NOT happened yet when the report is produced.  To decide whether
the bytes it is about to write carry taint from the reproducer's own stores
(labelled via kdo_store_callback / the zero-page labelling below) we must either
read the *source* buffer while we still have it, or wait for the store to land
and read the *destination*.

Three report shapes are handled, described declaratively in BUG_CATALOGUE:

  1. __asan_memcpy(dst, src, n)   — the helper is handed the source buffer, so
                                    the taint can be read at once, before the
                                    store.  `source: True`.
  2. __kasan_check_write(ptr, n)  — destination and size only, no source.  We
  3. kasan_check_range(ptr,n,w,ip)  have to watch for the store and read the
                                    taint on the destination.  `dest: True`.

Case 3 executes entirely inside a kernel worker thread, not the reproducer, so
nothing here may assume the reproducer is `current`.

PRUNING
-------
These helpers are called millions of times per second of guest time.  A hit only
counts when the *call stack* matches the one in the KASAN report — that is the
`pedigree` field of a catalogue entry, and it is checked with pure integer
comparisons before anything touches guest memory.

CONFIRMATION
------------
A matching call stack is necessary but not sufficient: the same call site is hit
many times and only one of those calls is the out-of-bounds one.  kasan_report()
is the discriminator — KASAN only calls it when a range check has actually
failed.  So every matching hit opens a *window*, the window collects a taint
reading, and the reading is only promoted to a violation if kasan_report() fired
while that window was open.  Depending on the case the report arrives before the
reading (cases 2/3: the report runs inside the helper, the store comes after) or
after it (case 1: the reading is taken at helper entry, the report runs inside).
Both orders are handled; see OobWindow.

WHERE TAINT CAN BE READ  (the reason for the three-callback dance)
-----------------------------------------------------------------
cb_virt_mem_after_write is the obvious place to look after a store and it is the
one place guaranteed to give the wrong answer.  It is dispatched from inside the
store helper (panda/src/cb-support.c:392, called from softmmu_template.h), but
taint2 emits the shadow-memory update for that same store as SEPARATE calls
placed AFTER the store's CallInst (PandaTaintVisitor::insertTaintBulk ->
insertLogPop then taint_copy, llvm_taint_lib.cpp:747-781).  Inside the write
callback the shadow therefore still holds the pre-store state: right value, zero
taint.

The first safe read point is after_insn_exec, whose helper translate.c emits
immediately after disas_insn() finishes the instruction (target/i386/translate.c
:8551-8557).  Within one guest instruction the order is:

    call helper_le_stq_mmu_panda(...)   the store; write watcher fires here
    call taint_memlog_pop / taint_copy  taint2 updates shadow memory
    call helper_panda_after_insn_exec   our probe: taint is now visible, and no
                                        later guest instruction has run

So: __kasan_check_write/kasan_check_range give dst+size, the write watcher says
"a store landed in [dst,dst+size) at pc X", and after_insn_exec reads the taint
one instruction later.

COST, AND WHY THE PC GATE IS NOT PC-GATED ANY MORE
--------------------------------------------------
An earlier version restricted the after_insn_translate gate to the extent of the
flagged function, on the theory that this kept the KASAN report path free of
instrumentation.  That does not survive contact with real kernel code: `memcpy`
tail-jumps to `__memcpy`, which alternative-patches into `memcpy_orig`/`erms`
bodies at unrelated addresses, so the store executes outside any single
function's pc range and the probe was never emitted where it mattered.

The gate now returns True unconditionally, and the cost of that is small and
bounded, for reasons that are all checkable in the PANDA tree:

  * panda_callbacks_after_insn_translate() runs every enabled after_insn_translate
    callback for every instruction translated, whatever its pc (the MAKE_CALLBACK
    macro, panda/include/panda/callbacks/cb-macros.h).  The narrow gate was
    already paying the full Python translate-time cost; returning True adds none.
  * The exec-side cost is one extra `call helper_panda_after_insn_exec` per
    non-block-terminating guest instruction.  With the probe disabled that helper
    walks a one-element panda_cb_list and tests plist->enabled
    (cb-helper-impl.h:28-36) — tens of nanoseconds.
  * taint2 ignores helper_panda_* calls outright (llvm_taint_lib.cpp:1713), so
    the extra call adds no taint instrumentation and cannot perturb propagation.
  * The gate is only switched on once the reproducer execve's, after which taint2
    runs execution through the LLVM JIT with per-op taint_copy/taint_mix calls
    plus per-instruction volatile panda_guest_pc and rr_guest_instr_count stores
    (panda/llvm/tcg-llvm.cpp:1407-1420).  One more C call there is single-digit
    percent.

What is genuinely expensive is the *Python* side of a callback (pandare wraps
every one in _run_and_catch: cffi trampoline, hasattr, try/except — microseconds,
panda.py:2750).  That is governed by the enabled bit, not by the gate, so the
Python probe is armed as narrowly as possible:

    hook helper returns  -> arm the write watcher only    (report is behind us)
    watcher sees a store -> arm the after_insn_exec probe (fires next insn)
    probe reads taint    -> disarm both

Between those points the analysis costs one Python call per *store*, not per
instruction.

A call-depth shadow stack was considered for the arming step and is not needed —
and could not be built the obvious way.  pandare's callstack_callers() returns
`lim` entries and discards the real count (panda.py:950-964), and
callstack_instr's on_ret fires ONCE while popping frames i..end
(callstack_instr.cpp:388-411), so a +1/-1 counter driven by on_call/on_ret cannot
stay balanced.  It is also unnecessary: on_ret already reports *which function
returned*, so "we are back in the caller of the KASAN helper, with the report
behind us" is the single event on_ret(hook_addr) — the shadow stack's depth-zero
moment, obtained exactly and for free.

GETTING THE STORE TO EXECUTE
----------------------------
The destination probe only works if the OOB store actually runs, and for the
mem*() family on a stock kernel it usually does not.  kasan_check_range() is

    bool kasan_check_range(unsigned long addr, size_t size, bool write,
                           unsigned long ret_ip)
    {
            ...
            return !kasan_report(addr, size, write, ret_ip);   /* mm/kasan/generic.c */
    }

and kasan_report() returns true only when it actually printed something:

    if (unlikely(report_suppressed_sw()) || unlikely(!report_enabled())) {
            ret = false;                                      /* mm/kasan/report.c */
            goto out;
    }

    static bool report_enabled(void)
    {
            if (current->kasan_depth)                    return false;
            if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) return true;
            return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
    }

Compose that with KASAN's memcpy()/memmove()/memset() wrappers, which are the
only kasan_check_range() callers that ACT on the result (compiler-generated
__asan_store*() and instrument_write() both discard it — which is why the
__kasan_check_write case works), and you get a config where you can have the
report or the store, never both:

  * no kasan_multi_shot (what rrr boots with today — rrr/__init__.py:43 rebinds
    extra_qemu_kernel_args and the winning binding drops it): the FIRST OOB of
    the boot prints its report, kasan_report() returns true, the check returns
    false, and the wrapper returns NULL without copying.  Every LATER OOB is
    suppressed, kasan_report() returns false, the check "passes", and the copy
    does happen — but no report is printed for it.
  * with kasan_multi_shot: every report prints, so every mem*() check vetoes its
    copy and the store NEVER executes.  Strictly worse here.

There is no boot parameter that gives both.  kasan.fault=report|panic only
reaches end_report(); it does not change the return value.  So for the occurrence
whose report is PRINTED, the store cannot be made to happen by configuration —
memcpy() takes that decision itself.  What is left:

  1. A LATER occurrence of the same OOB in the same boot already stores, for free.
     One-shot suppression makes report_enabled() false from the second report
     onwards, so kasan_report() returns false, the check "passes", and __memcpy()
     runs.  Confirmation still works, because this module hooks the CALL to
     kasan_report() and that call happens either way — the function just
     early-returns.  So a second occurrence yields a destination window that is
     both confirmed AND has a real store, with no changes anywhere.
     Requires (a) the reproducer to re-trigger the bug and (b) the recording to
     extend past the first report — kdo stops draining serial output 30 s after
     the sentinel (kdo/__init__.py: IDLE_TIMEOUT), so lengthening that is the
     cheapest thing to try.  Check analysis1.json for a second hit on the target
     with confirmed_by_kasan_report=true before doing anything else.
     Do NOT add kasan_multi_shot if you are relying on this: it keeps every report
     enabled and therefore vetoes every copy.
  2. Read the SOURCE instead, and never depend on the store.  Where the report's
     faulting frame is a call to memcpy(), hooking memcpy itself hands you
     (dest, src, len) in rdi/rsi/rdx, so the taint on the bytes about to go out
     of bounds is readable before anything stores.  Works on the recordings you
     already have; this is the p9_read_work_src catalogue entry.  For a straight
     memcpy this is not a proxy for the destination reading but the same answer:
     taint2 copies labels byte-for-byte through the store, so src[0..n) and the
     post-store dst[0..n) carry identical labels.  It stops being equivalent only
     where the store is not a verbatim copy (memset, computed values, partial
     writes).
  3. Patch the wrappers so they stop vetoing (mm/kasan/shadow.c) — call both
     kasan_check_range()s for their side effects and __memcpy() unconditionally,
     the way the kernel did before the check results were made to veto the copy.
     The report still prints, so kdo's serial sentinel still fires, AND the store
     executes.  Then kasan_multi_shot becomes useful rather than harmful.  Needs a
     rebuild and a re-record.  See
     kernel-patches/0001-kasan-do-not-veto-mem-on-a-failed-range-check.patch.
  4. Deliberately burn KASAN_BIT_REPORTED during boot, before the snapshot, so
     every recording starts suppressed and every mem*() copy proceeds.  Rejected:
     the target report is then never printed either, so kdo's expect_prompt never
     matches and the recording is scored NO_CRASH.

RECORD/REPLAY HAZARDS
---------------------
  * Guest *virtual* reads (OSI, the VMA walk, virt_to_phys) run
    cpu_get_phys_page_debug(), which reads page-table entries through
    address_space_ldq().  That only reaches RR_DO_RECORD_OR_REPLAY on the
    non-direct/MMIO path (memory_ldst.inc.c:36-44); RAM-backed PTEs take the
    direct path and cannot perturb the log.  panda_virtual_memory_rw() does the
    same walk (panda/include/panda/common.h:252-272), so OSI reads carry exactly
    the same (small) exposure as virt_to_phys — v2p_range() batches walks for
    speed, not because the other readers are exempt.
  * pm.refresh() and taint_enable() are called only from on_call
    (AFTER_BLOCK_EXEC), never from on_ret (BEFORE_BLOCK_EXEC): at BEFORE_BLOCK_EXEC
    the block is about to run, and a divergence there is not recoverable.
  * This recording desynchronises from its log at a fixed point past the bug.
    Nothing can be written after that (see _write_analysis), so results are
    flushed to analysis1.json as each observation is finalised.
"""

from pandare import Panda

import rrr
# Re-use the exact same Panda/QEMU config that kdo uses for recording
from kdo import conf


def update_config(share_path=None):
	"""Publish kdo's Panda/QEMU config to rrr for the replay.

	`share_path` should be the SAME host directory that was passed to
	kdo.update_config() when the recording was made.  Recording adds
	`-fsdev local,... -device virtio-9p-pci,...` to the machine args; replaying
	without it gives the replayed machine a different PCI device set than the
	recorded one, which is a good way to make a replay diverge.  It is optional
	only because existing callers do not pass it.
	"""
	if share_path is not None:
		import kdo
		kdo.update_config(share_path)
		return
	print('[analysis1] WARNING: update_config() called without share_path — the '
		  'replayed machine will not have the virtio-9p device the recording had')
	rrr.update_config(conf)

import time
import json
import traceback
import re
import faulthandler
import tempfile

repro_pattern   = re.compile(r"\brepro$")
kworker_pattern = re.compile(r"^kworker/")

from .mappings import ProcessMappings
from cffi import FFI

# pandare's panda.get_process_name() LEAKS.  osi's get_current_process() mallocs
# an OsiProc plus a separate name string and pages list
# (panda/plugins/osi/osi_types.h:72-81), and pandare only reads proc.name and
# drops the pointer — nothing is ever freed.  In a hot path that leaks steadily
# for the whole replay.  Free all three ourselves,
# the same way kdo/analysis2/__init__.py:is_repro() does, and never call
# panda.get_process_name() from this module.
#
# NB ProcessMappings.refresh() still leaks one OsiProc per call; it is called
# rarely (mmap/brk returns and page-fault drains) so it is left alone.
_free_ffi = FFI()
_free_ffi.cdef("void free(void *);")
# dlopen(None) is the process's own symbol namespace, which already includes libc
# since libpanda links against it — no need for a hardcoded multiarch path.
_libc = _free_ffi.dlopen(None)


def process_name(panda, cpu):
	"""Current process name, or None — without leaking the OsiProc.

	Replacement for panda.get_process_name(); see the comment above."""
	proc = panda.plugins['osi'].get_current_process(cpu)
	if proc == panda.ffi.NULL:
		return None
	try:
		if proc.name == panda.ffi.NULL:
			return None
		return panda.ffi.string(proc.name).decode('utf-8', 'ignore')
	finally:
		if proc.name != panda.ffi.NULL:
			_libc.free(proc.name)
		if proc.pages != panda.ffi.NULL:
			_libc.free(proc.pages)
		_libc.free(proc)


# ---------------------------------------------------------------------------
# Bug catalogue
#
# One entry per KASAN report shape we know how to analyse.  Everything that is
# specific to a particular bug lives here; the machinery below is generic.
#
# Deriving these entries from the KASAN report text automatically is future
# work — the fields are deliberately just "symbol + offset", which is exactly
# what a report prints, so that step is a parser, not a redesign.
#
#   id        name used in the log and in analysis1.json
#   hook      kernel symbol whose *entry* we hook (callstack_instr's on_call
#             fires with the callee's pc, so this matches the function address)
#   args      how to pull the write target out of the argument registers:
#               'ptr_size'       (ptr, size)             rdi, rsi
#               'ptr_size_write' (ptr, size, is_write)   rdi, rsi, rdx
#               'memcpy'         (dst, src, size)        rdi, rsi, rdx
#   pedigree  call-stack constraints, ALL of which must hold.  Checked with
#             integer comparisons only, before any guest memory is touched:
#               ('frame', n, (sym, ...), off)  callers[n] == sym+off
#               ('anywhere', (sym, ...), off)  sym+off appears in callers
#             Each (sym, ...) tuple lists acceptable spellings of one symbol
#             (e.g. a .constprop.N suffix that may or may not be present).
#             The offsets are RETURN addresses — the KASAN report prints the
#             call site, the return address is the next instruction.
#   store_fn  the function whose return closes the window.  The OOB store
#             happens somewhere between `hook` returning and `store_fn`
#             returning; it does NOT have to be inside store_fn's own pc range
#             (memcpy -> __memcpy -> memcpy_orig is fine).
#   ctx       task the call must run in: 'repro', 'kworker' or 'any'
#   source    the hook is handed the source buffer: read its taint at hook
#             entry, before the store.  No store watching needed.
#   dest      no source buffer: watch for the store into [ptr, ptr+size) and
#             read the taint on those bytes afterwards.
#
# `source` and `dest` are independent; a catalogue entry may set both.  Setting
# `dest` on an entry whose store happens *inside* the hooked function (case 1)
# would need the probe armed across the KASAN report, which costs a Python
# callback per reported instruction — hence dest=False there.
# ---------------------------------------------------------------------------
BUG_CATALOGUE = (
	{
		'id':       'copy_to_urb',
		'hook':     '__asan_memcpy',
		'args':     'memcpy',
		'pedigree': (('frame', 0, ('copy_to_urb.constprop.0', 'copy_to_urb'), 0x309),),
		'store_fn': '__asan_memcpy',
		'ctx':      'repro',
		'source':   True,
		'dest':     False,
	},
	{
		'id':       'bitmap_ip_add',
		'hook':     '__kasan_check_write',
		'args':     'ptr_size',
		'pedigree': (('frame', 0, ('bitmap_ip_add',), 0x3c0),),
		'store_fn': 'bitmap_ip_add',
		'ctx':      'repro',
		'source':   False,
		'dest':     True,
	},
	{
		'id':       'p9_read_work',
		'hook':     'kasan_check_range',
		'args':     'ptr_size_write',
		# kasan_check_range        <- we are here
		#   memcpy                    callers[0] = retaddr inside memcpy
		#   _copy_to_iter+0x997       callers[1]
		#   ...
		#   p9_read_work+0x1f0        somewhere deeper
		'pedigree': (('frame', 1, ('_copy_to_iter',), 0x997),
					 ('anywhere', ('p9_read_work',), 0x1f0)),
		# The store is in memcpy's body (or whatever memcpy jumps to), not in
		# _copy_to_iter, so the window must stay open until memcpy returns.
		'store_fn': 'memcpy',
		'ctx':      'kworker',
		'source':   False,
		'dest':     True,
	},
	# Same bug, second route — and on a stock kernel the ONLY route that yields a
	# reading.  KASAN's memcpy() wrapper is
	#     if (!kasan_check_range(src,  len, false, _RET_IP_) ||
	#         !kasan_check_range(dest, len, true,  _RET_IP_))
	#             return NULL;
	#     return __memcpy(dest, src, len);
	# and kasan_check_range() returns `!kasan_report(...)`, so a check whose report
	# is actually PRINTED vetoes the copy: the OOB store never executes and the
	# destination probe above can only report 'store_never_executed'.  See
	# "GETTING THE STORE TO EXECUTE" in the module docstring.
	#
	# Hooking memcpy's own entry sidesteps all of that: rdi/rsi/rdx hold
	# (dest, src, len), so the taint on the bytes that are ABOUT to go out of
	# bounds can be read before anything stores — exactly case 1.  The pedigree is
	# also cheaper and more selective than the one above, because
	# _copy_to_iter+0x997 (the return address the report prints) is the immediate
	# caller rather than callers[1].
	#
	# Both entries are live on purpose: memcpy calls kasan_check_range, so both
	# windows are open across the same access and kasan_report confirms both.  The
	# source window produces the verdict; the destination window records whether
	# the store executed at all.
	{
		'id':       'p9_read_work_src',
		'hook':     'memcpy',
		'args':     'memcpy',
		# _copy_to_iter+0x997 alone would match every pipe/socket read that goes
		# through that call site, and each match costs an OSI walk plus a
		# source-buffer taint read.  Keep p9_read_work+0x1f0 in the pedigree to
		# prune those, exactly as the kasan_check_range entry does.
		'pedigree': (('frame', 0, ('_copy_to_iter',), 0x997),
					 ('anywhere', ('p9_read_work',), 0x1f0)),
		'store_fn': 'memcpy',
		'ctx':      'kworker',
		'source':   True,
		'dest':     False,
	},
)

# Depth requested from callstack_instr for pedigree matching and for the
# backtraces recorded in analysis1.json.
CALLER_DEPTH = 24

# Upper bound on how many bytes of a single buffer we resolve and query.  A
# KASAN size argument is attacker-influenced, and both the paddr resolution and
# the taint query are per byte.  Anything larger is clamped and reported as
# clamped rather than silently truncated.
MAX_TAINT_BYTES = 4096

PAGE_SIZE = 0x1000

# Kernel text on x86_64 with nokaslr.  Used to disambiguate symbols that exist
# in both vmlinux and the statically-linked reproducer ('memcpy' is the one that
# bites: rrr's symbol_map is last-writer-wins, so the userspace entry clobbers
# the kernel one).
KERNEL_TEXT_MIN = 0xffffffff00000000


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


def __replay(rootfs, kernel, record, _ignored_addresses, func_map, symbol_map,
			 enable_logging, stop_on_first_violation=True):
	"""stop_on_first_violation:
	  True  — end the replay as soon as one OOB write is confirmed tainted.  The
	          run exits cleanly, because it stops before this recording's desync
	          point (see the module docstring).
	  False — keep going and collect every violation.  The replay is then killed
	          by SIGABRT at the desync point, so results are flushed to
	          analysis1.json after every observation; see _write_analysis()."""
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

	# ------------------------------------------------------------------
	# Symbol resolution
	# ------------------------------------------------------------------

	def _ksym(name):
		"""Address of kernel symbol `name`, or None.

		symbol_map is last-writer-wins over every ELF rrr parsed, so a name that
		also exists in the reproducer binary (notably 'memcpy') resolves to the
		userspace one.  func_map is keyed by address, so both spellings survive
		there and we can pick the kernel-text entry."""
		sym = symbol_map.get(name)
		if sym is not None and sym.address >= KERNEL_TEXT_MIN:
			return sym.address
		for addr, f in func_map.items():
			if f.symbol == name and addr >= KERNEL_TEXT_MIN:
				return addr
		return None

	def _usym(name):
		"""Address of userspace symbol `name` (reproducer binary), or None."""
		sym = symbol_map.get(name)
		return sym.address if sym is not None else None

	def _first_ksym(names):
		"""First of `names` that resolves in kernel text, plus the name used."""
		for n in names:
			addr = _ksym(n)
			if addr is not None:
				return addr, n
		return None, names[0]

	kasan_report_addr    = _ksym('kasan_report')
	panic_addr           = _ksym('panic')
	handle_mm_fault_addr = _ksym('handle_mm_fault')
	kdo_store_cb_addr    = _usym('kdo_store_callback')
	sink_addr            = _usym('sink')

	print(f'[analysis1] kasan_report:    '
		  f'{hex(kasan_report_addr) if kasan_report_addr else "NOT FOUND"}')
	print(f'[analysis1] panic:           '
		  f'{hex(panic_addr) if panic_addr else "NOT FOUND"}')
	print(f'[analysis1] handle_mm_fault: '
		  f'{hex(handle_mm_fault_addr) if handle_mm_fault_addr else "NOT FOUND"}')
	print(f'[analysis1] kdo_store_callback: '
		  f'{hex(kdo_store_cb_addr) if kdo_store_cb_addr else "NOT FOUND"}')
	print(f'[analysis1] sink:            '
		  f'{hex(sink_addr) if sink_addr else "NOT FOUND"}')

	if kasan_report_addr is None:
		print('[analysis1] WARNING: kasan_report not in the symbol table — no '
			  'observation can ever be confirmed as out of bounds')

	def _resolve_target(t):
		"""Turn a catalogue entry into a runtime target, or None if a symbol is
		missing.  A missing symbol is normal: the catalogue covers several bugs
		and only one of them exists in any given kernel/reproducer pair."""
		hook_addr = _ksym(t['hook'])
		if hook_addr is None:
			return None, f"hook {t['hook']} not found"
		store_addr = _ksym(t['store_fn'])
		if store_addr is None:
			return None, f"store_fn {t['store_fn']} not found"

		pedigree = []
		for c in t['pedigree']:
			if c[0] == 'frame':
				_, idx, names, off = c
				base, used = _first_ksym(names)
				if base is None:
					return None, f"pedigree symbol {names[0]} not found"
				pedigree.append(('frame', idx, base + off, f'{used}+{off:#x}'))
			elif c[0] == 'anywhere':
				_, names, off = c
				base, used = _first_ksym(names)
				if base is None:
					return None, f"pedigree symbol {names[0]} not found"
				pedigree.append(('anywhere', None, base + off, f'{used}+{off:#x}'))
			else:
				return None, f"unknown pedigree constraint {c[0]!r}"

		return dict(t, hook_addr=hook_addr, store_addr=store_addr,
					pedigree=pedigree), None

	targets      = []
	hook_targets = {}          # hook address -> [target, ...]
	target_info  = {}          # for analysis1.json
	for entry in BUG_CATALOGUE:
		resolved, why = _resolve_target(entry)
		if resolved is None:
			print(f"[analysis1] target {entry['id']!r} unavailable: {why}")
			target_info[entry['id']] = {'available': False, 'reason': why}
			continue
		targets.append(resolved)
		hook_targets.setdefault(resolved['hook_addr'], []).append(resolved)
		pedigree_desc = [f'{kind}{"" if idx is None else f"[{idx}]"}='
						 f'{desc}@0x{addr:x}'
						 for kind, idx, addr, desc in resolved['pedigree']]
		target_info[entry['id']] = {
			'available': True,
			'hook':      f"{entry['hook']}@0x{resolved['hook_addr']:x}",
			'store_fn':  f"{entry['store_fn']}@0x{resolved['store_addr']:x}",
			'pedigree':  pedigree_desc,
			'ctx':       entry['ctx'],
			'evidence':  ([] + (['source'] if entry['source'] else [])
							 + (['dest'] if entry['dest'] else [])),
		}
		print(f"[analysis1] target {entry['id']!r}: hook="
			  f"{entry['hook']}@0x{resolved['hook_addr']:x} "
			  f"store_fn={entry['store_fn']}@0x{resolved['store_addr']:x} "
			  f"ctx={entry['ctx']} pedigree={pedigree_desc}")

	if not targets:
		print('[analysis1] WARNING: no catalogue target resolved — this replay '
			  'can only produce the taint-labelling side of the analysis')

	# Cheapest possible rejection for a hook call: the shallowest 'frame'
	# constraint of each target on that hook.  A call passes if ANY of them
	# matches, so this can only reject calls no target could have accepted — and
	# it needs a 1- or 2-deep call stack rather than the full CALLER_DEPTH one.
	# Disabled (None) for a hook where some target has no 'frame' constraint at
	# all, since then there is nothing shallow to test.
	hook_prefilter = {}
	for _haddr, _tl in hook_targets.items():
		_checks, _ok = [], True
		for _t in _tl:
			_frames = [(idx, want) for kind, idx, want, _d in _t['pedigree']
					   if kind == 'frame']
			if not _frames:
				_ok = False
				break
			_checks.append(min(_frames))
		hook_prefilter[_haddr] = sorted(set(_checks)) if _ok else None

	# Call targets on_call does something for, other than the hooks themselves.
	# Membership is a set lookup with no guest reads, which is what lets the
	# OSI-based process check stay off the hot path: on_call is invoked for every
	# call instruction in the guest.
	interesting_call_addrs = {a for a in (
		kasan_report_addr, kdo_store_cb_addr, sink_addr, panic_addr,
		handle_mm_fault_addr,
	) if a is not None}

	# ------------------------------------------------------------------
	# Analysis state
	# ------------------------------------------------------------------

	analysis = {'targets': target_info}
	# Maps label ID (int) -> {'virt_addr': hex str, 'backtrace': [...], ...}
	label_map = {}
	# Counters are in a dict so nested callbacks can bump them without `nonlocal`
	# gymnastics.  Hook counters count ALL calls in ALL tasks — they exist to say
	# how much noise the pedigree filter is removing, so they must not be gated.
	ctr = {'hook_calls': {}, 'target_hits': {}, 'kasan_report': 0, 'labels': 1}
	# Set once the answer is in and panda.end_analysis() has been queued.  The
	# stop is asynchronous (queue_async(stop_run)) so hooks keep firing for a
	# while; and panda.ending makes pandare's enable_callback() a silent no-op
	# (panda.py:2908-2916), so anything armed after this point could never fire
	# and would report a bogus "no store observed" for a store that did happen.
	# 'windows' holds every window still open.  More than one can be open at a
	# time because a hook may itself call another hook (memcpy -> kasan_check_range)
	# and both describe the same access; kasan_report then confirms both.  Only one
	# of them may be a destination window, though, since there is a single
	# watcher/probe callback pair — 'dest_window' is that one.
	state = {'stopped': False, 'windows': [], 'dest_window': None}

	def log(s):
		if enable_logging:
			print(s, file=outfile)

	def _write_analysis():
		"""Flush the consolidated analysis to ./analysis1.json.

		Called after every finalised observation, not only at the end, because in
		run-to-completion mode the replay is eventually killed by SIGABRT at this
		recording's desync point — and that cannot be rescued from Python.  rrr
		runs __replay in a multiprocessing child (rrr/__init__.py:799), abort() is
		raised inside libpanda from C, and a signal.signal() handler never gets to
		run: CPython's handler only executes when the interpreter next checks
		between bytecodes, which never happens because abort() terminates the
		process as soon as its C trampoline returns.  Verified empirically — a
		Python SIGABRT handler fires for os.kill() but not for a C abort().  So
		results must be on disk BEFORE the crash; there is no writing them after."""
		analysis['counters'] = {
			'hook_calls':   dict(ctr['hook_calls']),
			'target_hits':  dict(ctr['target_hits']),
			'kasan_report': ctr['kasan_report'],
		}
		analysis['total_taint_labels'] = ctr['labels'] - 1
		analysis['process_mappings'] = len(pm.mappings)
		with open('./analysis1.json', 'w') as f:
			f.write(json.dumps(analysis, indent=2))

	# ------------------------------------------------------------------
	# Guest introspection helpers
	# ------------------------------------------------------------------

	def enable_taint():
		if not panda.taint_enabled():
			panda.taint_enable()

	def _labels_for_paddr(paddr):
		"""Taint labels on physical address `paddr`, or None.

		Does NOT check taint_enabled() — callers must guard that themselves so
		the None return unambiguously means "untainted", not "taint off"."""
		result = panda.taint_get_ram(paddr)
		if result is None:
			return None
		return result.get_labels()

	def v2p_range(cpu, base, length):
		"""Translate [base, base+length) with one page-table walk per PAGE, not
		per byte.  Returns `length` entries, each a paddr or None if unmapped.

		A virtual page maps to one contiguous physical page, so translating every
		byte separately repeats the same walk up to 4096 times.  See the
		record/replay notes in the module docstring for the second reason to keep
		the walk count down."""
		out = []
		off = 0
		while off < length:
			va = base + off
			chunk = min(PAGE_SIZE - (va & (PAGE_SIZE - 1)), length - off)
			pa = panda.virt_to_phys(cpu, va)
			if pa == 0xFFFFFFFFFFFFFFFF:
				out.extend([None] * chunk)
			else:
				out.extend(range(pa, pa + chunk))
			off += chunk
		return out

	def read_taint_range(cpu, base, length, what):
		"""Taint on [base, base+length).

		Returns (tainted_bytes, meta) where tainted_bytes maps byte offset ->
		{'labels': [...], 'resolved': [...]} and meta records how much of the
		range we could actually look at.  Uses one page-table walk per page and
		then touches shadow memory only."""
		meta = {'requested': length, 'read': 0, 'untranslatable': 0,
				'clamped': False, 'taint_enabled': panda.taint_enabled()}
		tainted = {}
		if length <= 0:
			return tainted, meta
		if length > MAX_TAINT_BYTES:
			meta['clamped'] = True
			length = MAX_TAINT_BYTES
		meta['read'] = length
		if not meta['taint_enabled']:
			print(f'[analysis1]   WARNING: taint not enabled — cannot read taint '
				  f'on {what} 0x{base:x}+{length}')
			return tainted, meta
		paddrs = v2p_range(cpu, base, length)
		for off in range(length):
			paddr = paddrs[off]
			if paddr is None:
				meta['untranslatable'] += 1
				continue
			lbls = _labels_for_paddr(paddr)
			if lbls:
				resolved = [label_map[l] for l in lbls if l in label_map]
				tainted[off] = {'labels': list(lbls), 'resolved': resolved}
				log(f'  taint: {what}[{off}] @ 0x{base + off:x} (pa 0x{paddr:x}) '
					f'labels={lbls} resolved={resolved}')
		return tainted, meta

	def callers(cpu, depth=CALLER_DEPTH):
		"""Return the call stack, shortest-first, with the padding removed.

		pandare's callstack_callers() allocates `depth` slots, asks
		callstack_instr to fill them, then returns ALL of them and throws away
		the count it was given (panda.py:950-964).  Every short stack therefore
		comes back padded with zeros, which silently turns `callers[0]` into 0 on
		an empty stack and makes `len(callers)` meaningless."""
		raw = panda.callstack_callers(depth, cpu)
		while raw and raw[-1] == 0:
			raw.pop()
		return raw

	def _in_repro(cpu):
		"""True if the current process is the reproducer.

		This asks OSI, i.e. it walks the guest task_struct, so it must only be
		called once a cheaper filter has already rejected the uninteresting calls.

		Deliberately NOT panda_current_asid() (env->cr[3]), which is register-only
		and therefore tempting.  cr3 is not equivalent to `current`:
		  - it over-matches: kernel threads have no mm and run on the previous
		    task's page tables (lazy TLB), so a kworker scheduled after the repro
		    still carries the repro's cr3;
		  - it can under-match: with KPTI the kernel and user mappings are
		    different PGDs, so one process has two cr3 values depending on the
		    context you sample in, and PCID/noflush bits ride in the low and top
		    bits.  Learning one value and comparing against the other silently
		    stops matching — and every hook we care about fires in kernel context.
		"""
		pname = process_name(panda, cpu)
		return bool(pname) and bool(repro_pattern.search(pname))

	def _in_kworker(cpu):
		"""True if the current process is any kworker thread.

		The p9_read_work bug executes entirely inside a kworker, never inside the
		reproducer process."""
		pname = process_name(panda, cpu)
		return bool(pname) and bool(kworker_pattern.match(pname))

	def _ctx_ok(cpu, want):
		if want == 'any':
			return True
		if want == 'repro':
			return _in_repro(cpu)
		if want == 'kworker':
			return _in_kworker(cpu)
		raise ValueError(f'unknown ctx {want!r}')

	# ------------------------------------------------------------------
	# Deferred work
	#
	# on_ret fires from PANDA_CB_BEFORE_BLOCK_EXEC, where the block is about to
	# execute; on_call fires from PANDA_CB_AFTER_BLOCK_EXEC, where it has already
	# finished.  pm.refresh(), taint_enable() and taint labelling are therefore
	# all done from the on_call side, and on_ret only queues.
	# ------------------------------------------------------------------

	# cpu_index -> fault address recorded at handle_mm_fault entry.  Keyed by CPU
	# index so SMP replays don't clobber each other; kdo replays are single-CPU
	# in practice, but the guard is free.
	handle_mm_fault_pending = {}
	pending = {'refresh': False, 'zero_pages': []}

	# ------------------------------------------------------------------
	# Callbacks used by the destination probe
	# ------------------------------------------------------------------

	@panda.cb_after_insn_translate(name='oob_probe_gate', enabled=False)
	def oob_probe_gate(cpu, pc):
		"""Translate-time gate: emit the after_insn_exec helper everywhere.

		Deliberately not pc-restricted — see "COST" in the module docstring.  The
		helper is cheap while the probe is disabled; being unconditional is what
		lets the probe see a store that executes in a jumped-to or tail-called
		body (memcpy -> __memcpy -> memcpy_orig) instead of only inside the
		flagged function's own extent."""
		return True

	@panda.cb_virt_mem_after_write(name='oob_write_watcher', enabled=False)
	def oob_write_watcher(cpu, pc, addr, size, buf):
		"""dst-keyed detector for the OOB store.

		Its only jobs are to record that a write landed in [dst, dst+size) and to
		arm the taint probe.  It deliberately does NOT read taint: at this point
		taint2's taint_copy for this very store has not run yet, so the shadow
		still holds the pre-store state.  It reads no guest memory either — the
		written value comes from `buf`."""
		w = state['dest_window']
		if w is None or not w.watching:
			return
		if addr + size <= w.dst or addr >= w.dst + w.watch_size:
			return
		# PANDA hands us (uint8_t *)&val where val is a uint64_t, so never read
		# more than 8 bytes out of it regardless of the access width.
		val = int.from_bytes(bytes(panda.ffi.buffer(buf, min(size, 8))), 'little')
		w.note_store(pc, addr, size, val)

	@panda.cb_after_insn_exec(name='oob_probe', enabled=False)
	def oob_probe(cpu, pc):
		"""Fires after a completed guest instruction, once a store to dst landed.

		Armed by oob_write_watcher, so the first firing is the instruction that
		did the store — by which point taint2 has already updated the shadow.

		NB `pc` is the NEXT instruction's address: translate.c advances pc_ptr via
		disas_insn() before emitting this helper (target/i386/translate.c:8551)."""
		w = state['dest_window']
		if w is None or not w.store_seen or w.taint_read:
			return 0
		w.read_dest_taint(cpu, pc)
		return 0

	def _set_callback(name, on, obj, attr):
		"""Flip plist->enabled for a callback, idempotently, mirroring the state
		into `obj.attr` so the window always knows what is armed.

		Legal from inside another callback: panda_enable_callback_with_context()
		only writes plist->enabled and never mutates the list
		(panda/src/callbacks.c:699-726), and the lists are per callback type.  No
		retranslation is needed either — the after_insn_exec helper is already in
		the generated code because the gate has been on since the reproducer
		execve'd, so enabling the probe takes effect on the very next instruction."""
		if getattr(obj, attr) == on:
			return
		if on:
			panda.enable_callback(name)
		else:
			panda.disable_callback(name)
		setattr(obj, attr, on)

	# ------------------------------------------------------------------
	# One candidate observation
	# ------------------------------------------------------------------

	class OobWindow:
		"""A single matching hook call, and the taint evidence gathered from it.

		Lifecycle::

		    open()                target hit: dst/size captured; source taint read
		                          if the hook has a source buffer.  Nothing is
		                          armed yet — we are still inside the KASAN
		                          helper, and the report runs here.
		    go_live()             on_ret(hook): the helper returned, so the report
		                          is behind us and control is back in the caller.
		                          Arm the write watcher.
		    note_store()          the watcher saw a write into [dst,dst+size).
		                          Arm the taint probe.
		    read_dest_taint()     the probe fired one instruction later; read the
		                          shadow.
		    note_report()         kasan_report() ran while this window was open:
		                          the access really is out of bounds.
		    close()               on_ret(store_fn), or superseded, or end of run.

		The window is finalised as soon as both a reading and the kasan_report
		confirmation exist, in whichever order they arrive, or at close() with
		whatever it has.
		"""

		__slots__ = ('target', 'hit', 'entry', 'dst', 'src', 'req_size',
					 'watch_size', 'armed_by', 'cpu_index', 'state',
					 'watching', 'probing', 'store_seen', 'store_count',
					 'first_store_pc', 'first_store_val', 'last_store_pc',
					 'last_store_val', 'taint_read', 'reading', 'confirmed',
					 'instr_at_open')

		def __init__(self, cpu, target, hit, entry):
			self.target     = target
			self.hit        = hit
			self.entry      = entry
			self.dst        = None
			self.src        = None
			self.req_size   = 0
			self.watch_size = 0
			self.armed_by   = process_name(panda, cpu)
			self.cpu_index  = cpu.cpu_index
			self.state      = 'open'
			self.watching   = False
			self.probing    = False
			self.store_seen = False
			self.store_count = 0
			self.first_store_pc = None
			self.first_store_val = None
			self.last_store_pc = None
			self.last_store_val = None
			self.taint_read = False
			self.reading    = None      # {'kind': 'source'|'dest', ...}
			self.confirmed  = False
			self.instr_at_open = panda.rr_get_guest_instr_count()

		# -- identity -------------------------------------------------------

		@property
		def hook_addr(self):
			return self.target['hook_addr']

		@property
		def store_addr(self):
			return self.target['store_addr']

		@property
		def wants_dest(self):
			return self.target['dest']

		@property
		def closed(self):
			return self.state == 'closed'

		def same_ctx(self, cpu):
			"""True if `cpu` is executing the same task that opened the window.

			Keyed on task_struct->comm, recorded at open time.  Without this, any
			other process returning from a function at the same address — the
			reproducer calling memcpy while a kworker's window is live — would
			steal the window's events."""
			if cpu.cpu_index != self.cpu_index:
				return False
			return process_name(panda, cpu) == self.armed_by

		# -- setup ----------------------------------------------------------

		def capture(self, cpu, dst, size, src=None):
			"""Record the write target and resolve the source taint, if any."""
			self.dst      = dst
			self.src      = src
			self.req_size = size
			if size <= 0:
				self.watch_size = 0
			elif size > MAX_TAINT_BYTES:
				self.watch_size = MAX_TAINT_BYTES
			else:
				self.watch_size = size
			if self.watch_size != size:
				print(f'[analysis1]   window #{self.hit}: size={size} from '
					  f'{self.target["hook"]} is outside [1, {MAX_TAINT_BYTES}] — '
					  f'watching {self.watch_size} byte(s) only')

			self.entry['dst'] = hex(dst)
			self.entry['size'] = size
			self.entry['watch_size'] = self.watch_size

			if self.target['source'] and src is not None:
				tainted, meta = read_taint_range(cpu, src, size, 'src')
				self.entry['src'] = hex(src)
				self.reading = {'kind': 'source', 'base': hex(src),
								'tainted_bytes': tainted, 'meta': meta}
				if tainted:
					print(f'[analysis1]   source taint: {len(tainted)}/'
						  f'{meta["read"]} bytes at 0x{src:x} carry labels')
				else:
					print(f'[analysis1]   source taint: none on 0x{src:x}+'
						  f'{meta["read"]}')
				self._maybe_finalise()
				if self.closed:
					return

			if self.wants_dest and self.watch_size == 0:
				# Nothing to watch and nothing to read: do not let this masquerade
				# as a taint negative later on.
				self.state = 'waiting'
				print(f'[analysis1]   dest probe NOT armed: unusable size={size}')
			elif self.wants_dest:
				self.state = 'armed'
				print(f'[analysis1]   dest probe armed: task={self.armed_by!r} '
					  f'dst=0x{dst:x} watch={self.watch_size} — watcher stays off '
					  f'until {self.target["hook"]} returns')
			else:
				self.state = 'waiting'   # only waiting for kasan_report now

		# -- state transitions ----------------------------------------------

		def go_live(self):
			"""The hooked helper returned: the KASAN report is behind us and we
			are back in the caller, one instruction before the store at worst.
			Arm the write watcher only — the per-instruction probe stays off until
			a store actually lands."""
			if self.state != 'armed':
				return
			self.state = 'live'
			_set_callback('oob_write_watcher', True, self, 'watching')
			print(f'[analysis1]   dest probe live: {self.target["hook"]} returned, '
				  f'watching writes to 0x{self.dst:x}+{self.watch_size}')

		def note_store(self, pc, addr, size, val):
			self.store_count += 1
			self.last_store_pc  = pc
			self.last_store_val = val
			if not self.store_seen:
				self.store_seen = True
				self.first_store_pc  = pc
				self.first_store_val = val
				print(f'[analysis1]   store landed pc=0x{pc:x} addr=0x{addr:x} '
					  f'size={size} value=0x{val:x} — arming taint probe')
			# Arm the probe: it fires after the instruction that just stored, at
			# which point taint2 has updated the shadow for it.
			_set_callback('oob_probe', True, self, 'probing')

		def read_dest_taint(self, cpu, probe_pc):
			"""Read taint on the destination bytes.

			Touches shadow memory only: the written value came from the watcher's
			buffer, and the paddrs are resolved here from inside translated code —
			which is a page-table walk on RAM-backed PTEs, i.e. the direct path in
			address_space_ldq() and therefore log-neutral (module docstring)."""
			tainted, meta = read_taint_range(cpu, self.dst, self.watch_size, 'dst')

			# probe_pc is the pc AFTER the completed instruction, so this
			# difference is that instruction's length.  If it is not a plausible
			# length we are not on the storing instruction itself: translate.c
			# suppresses the helper for block-terminating instructions
			# (`&& !dc->is_jmp`), which is exactly what happens for `rep movs`
			# — the probe then fires in the following block, after taint2 has
			# processed every iteration.  That is still a correct reading, just
			# not an adjacent one, so this is recorded rather than warned about.
			delta = (probe_pc - self.last_store_pc
					 if self.last_store_pc is not None else None)
			adjacent = delta is not None and 0 < delta <= 15

			self.taint_read = True
			self.reading = {
				'kind': 'dest', 'base': hex(self.dst),
				'tainted_bytes': tainted, 'meta': meta,
				'probe_pc': hex(probe_pc), 'probe_adjacent': adjacent,
				'probe_delta': delta,
			}
			if not adjacent:
				print(f'[analysis1]   note: probe pc=0x{probe_pc:x} is not adjacent '
					  f'to the last store pc=0x{self.last_store_pc:x} (delta={delta}) '
					  f'— the store ended its translation block (e.g. rep movs); '
					  f'taint was read after that block completed')
			self._maybe_finalise()
			if self.closed:
				return

			# Confirmation has not arrived yet, so this call may still turn out to
			# be an in-bounds one.  Stash the reading and stand the per-instruction
			# probe back down — leaving it enabled would cost a Python callback per
			# guest instruction for the rest of the window.  The watcher stays on,
			# so a later store into dst re-arms the probe and refreshes the reading;
			# that is what makes "the last reading before kasan_report" the one we
			# report.
			self.taint_read = False
			_set_callback('oob_probe', False, self, 'probing')

		def note_report(self):
			"""kasan_report() ran while this window was open."""
			if self.confirmed or self.closed:
				return
			self.confirmed = True
			print(f'[analysis1] kasan_report fired inside window #{self.hit} '
				  f'({self.target["id"]}) — the access really is out of bounds')
			self._maybe_finalise()

		def _maybe_finalise(self):
			if self.reading is not None and self.confirmed:
				self.finalise('reading complete and kasan_report seen')

		def close(self, reason):
			if self.closed:
				return
			self.finalise(reason)

		# -- results --------------------------------------------------------

		def _outcome(self):
			if not self.confirmed:
				# The pedigree matched but KASAN did not complain: this call was
				# an in-bounds check, not the reported one.  Never a taint
				# negative.
				return 'unconfirmed'
			if self.reading is None:
				if self.wants_dest and not self.store_seen:
					return 'store_never_executed'
				if self.wants_dest:
					return 'store_not_read'
				return 'no_reading'
			if not self.reading['meta']['taint_enabled']:
				return 'taint_off'
			if self.reading['tainted_bytes']:
				return 'tainted'
			return 'untainted'

		def finalise(self, reason):
			if self.closed:
				return
			self.state = 'closed'
			_set_callback('oob_write_watcher', False, self, 'watching')
			_set_callback('oob_probe', False, self, 'probing')

			outcome = self._outcome()
			result = {
				'target':   self.target['id'],
				'hit':      self.hit,
				'outcome':  outcome,
				'reason':   reason,
				'confirmed_by_kasan_report': self.confirmed,
				'dst':      hex(self.dst) if self.dst is not None else None,
				'size':     self.req_size,
				'watch_size': self.watch_size,
				'stores_seen': self.store_count,
				'first_store_pc':  hex(self.first_store_pc) if self.first_store_pc is not None else None,
				'first_store_val': hex(self.first_store_val) if self.first_store_val is not None else None,
				'last_store_pc':   hex(self.last_store_pc) if self.last_store_pc is not None else None,
				'last_store_val':  hex(self.last_store_val) if self.last_store_val is not None else None,
				'guest_instrs': panda.rr_get_guest_instr_count() - self.instr_at_open,
				'reading':  self.reading,
			}
			# The hit entry keeps a one-line verdict; the full record lives in
			# analysis['observations'] so the JSON does not carry it twice.
			self.entry['outcome'] = outcome
			self.entry['confirmed_by_kasan_report'] = self.confirmed
			analysis.setdefault('observations', []).append(result)

			self._report(outcome, result)

			if outcome == 'tainted':
				analysis['violation'] = result
			# Get it on disk now — in run-to-completion mode nothing can be
			# written once the replay hits its desync point.
			_write_analysis()

			if self in state['windows']:
				state['windows'].remove(self)
			if state['dest_window'] is self:
				state['dest_window'] = None

			if outcome == 'tainted' and stop_on_first_violation:
				print('[analysis1] OOB taint confirmed — ending the analysis before '
					  'the replay reaches its divergence point')
				state['stopped'] = True
				panda.end_analysis()
			elif outcome == 'tainted':
				print(f'[analysis1] OOB taint confirmed at hit #{self.hit} — '
					  f'collecting further violations (stop_on_first_violation=False)')

		def _report(self, outcome, result):
			"""Human-readable verdict.  The point of distinguishing these is that
			"the store never ran" must never be reported as "no taint"."""
			tag  = f'{self.target["id"]} hit #{self.hit}'
			read = self.reading
			if outcome == 'tainted':
				n = len(read['tainted_bytes'])
				print(f'[analysis1] *** OOB TAINT CONFIRMED ({tag}): {n}/'
					  f'{read["meta"]["read"]} {read["kind"]} bytes at '
					  f'{read["base"]} carry taint ***')
				for off, info in sorted(read['tainted_bytes'].items()):
					print(f'[analysis1]     {read["kind"]}[{off}] '
						  f'labels={info["labels"]} resolved={info["resolved"]}')
			elif outcome == 'untainted':
				print(f'[analysis1] *** OOB WRITE NOT TAINTED ({tag}): none of the '
					  f'{read["meta"]["read"]} {read["kind"]} bytes at '
					  f'{read["base"]} carry taint ***')
			elif outcome == 'unconfirmed':
				print(f'[analysis1] ({tag}) call stack matched but kasan_report did '
					  f'not fire — this call was in bounds, not the reported one '
					  f'[{result["reason"]}]')
			elif outcome == 'store_never_executed':
				print(f'[analysis1] *** INCONCLUSIVE ({tag}): no write to '
					  f'0x{self.dst:x} was ever observed, so this is NOT a taint '
					  f'negative [{result["reason"]}] ***')
				print('[analysis1]   Expected when the caller ACTS on the check\'s '
					  'return value.  KASAN\'s mem*() wrappers do: '
					  '`if (!kasan_check_range(...)) return NULL;`, and '
					  'kasan_check_range() returns `!kasan_report(...)` — so a check '
					  'whose report was PRINTED vetoes the copy and there is no '
					  'store to observe.  Not a taint negative.  See "GETTING THE '
					  'STORE TO EXECUTE" at the top of this file: either patch the '
					  'wrappers and re-record, or rely on a source-reading target '
					  '(here: p9_read_work_src) which needs no store at all.')
			elif outcome == 'store_not_read':
				print(f'[analysis1] *** INCONCLUSIVE ({tag}): a store landed at '
					  f'pc={result["last_store_pc"]} but the probe never read the '
					  f'shadow [{result["reason"]}] ***')
			elif outcome == 'taint_off':
				print(f'[analysis1] *** INCONCLUSIVE ({tag}): taint2 was not enabled '
					  f'when the reading was taken ***')
			else:
				print(f'[analysis1] *** INCONCLUSIVE ({tag}): {outcome} '
					  f'[{result["reason"]}] ***')

			if read and read['meta']['untranslatable']:
				print(f'[analysis1]   note: {read["meta"]["untranslatable"]}/'
					  f'{read["meta"]["read"]} bytes were not translatable')
			if read and read['meta']['clamped']:
				print(f'[analysis1]   note: size clamped from '
					  f'{read["meta"]["requested"]} to {read["meta"]["read"]} bytes '
					  f'(MAX_TAINT_BYTES)')
			log(f'{tag}: outcome={outcome} reason={result["reason"]}')

	# ------------------------------------------------------------------
	# Hook dispatch
	# ------------------------------------------------------------------

	def _pedigree_matches(target, stack):
		for kind, idx, want, _desc in target['pedigree']:
			if kind == 'frame':
				if idx >= len(stack) or stack[idx] != want:
					return False
			else:  # 'anywhere'
				if want not in stack:
					return False
		return True

	def _hook_args(cpu, target):
		"""(dst, size, src) for this target's argument convention.

		x86_64 SysV: arg0=rdi arg1=rsi arg2=rdx arg3=rcx."""
		kind = target['args']
		if kind == 'ptr_size':
			return panda.arch.get_arg(cpu, 0), panda.arch.get_arg(cpu, 1), None
		if kind == 'ptr_size_write':
			# kasan_check_range(addr, size, write, ret_ip): reads are not our
			# problem, and there are far more of them than writes.
			if not panda.arch.get_arg(cpu, 2):
				return None, None, None
			return panda.arch.get_arg(cpu, 0), panda.arch.get_arg(cpu, 1), None
		if kind == 'memcpy':
			# __asan_memcpy(to, from, size)
			return (panda.arch.get_arg(cpu, 0), panda.arch.get_arg(cpu, 2),
					panda.arch.get_arg(cpu, 1))
		raise ValueError(f'unknown args convention {kind!r}')

	def _on_hook_call(cpu, addr, tlist):
		"""A call to one of the catalogue hooks.

		Order matters for cost: the pedigree check is integer comparisons on the
		call stack, which is a C call with no guest reads, so it runs BEFORE the
		OSI-based context check."""
		hook_name = tlist[0]['hook']
		ctr['hook_calls'][hook_name] = ctr['hook_calls'].get(hook_name, 0) + 1

		# These helpers are among the hottest functions in a KASAN kernel, so
		# reject with the shallowest call-stack query that can decide it before
		# paying for a full-depth one.
		pre = hook_prefilter.get(addr)
		if pre is not None:
			shallow = callers(cpu, max(i for i, _ in pre) + 1)
			if not any(i < len(shallow) and shallow[i] == want
					   for i, want in pre):
				return

		stack = callers(cpu)
		for target in tlist:
			if not _pedigree_matches(target, stack):
				continue
			if not _ctx_ok(cpu, target['ctx']):
				continue

			dst, size, src = _hook_args(cpu, target)
			if dst is None:
				continue

			hit = ctr['target_hits'].get(target['id'], 0) + 1
			ctr['target_hits'][target['id']] = hit

			entry = {
				'target':    target['id'],
				'hit':       hit,
				'hook':      target['hook'],
				'backtrace': [hex(a) for a in stack],
			}
			analysis.setdefault('target_hits', {}) \
					.setdefault(target['id'], []).append(entry)

			# Close what this hit supersedes: any open window for the SAME target
			# (that is what makes the reported reading the LAST one before
			# kasan_report), and — if this one needs the store watcher — any other
			# open destination window, since there is only one watcher/probe pair.
			for prev in list(state['windows']):
				if prev.closed:
					continue
				if prev.target['id'] == target['id']:
					print(f'[analysis1]   window #{prev.hit} ({prev.target["id"]}) '
						  f'still open — closing it before opening #{hit}')
					prev.close('superseded by a later hit on the same target')
				elif target['dest'] and prev.wants_dest:
					print(f'[analysis1]   destination window #{prev.hit} '
						  f'({prev.target["id"]}) still open — only one store '
						  f'watcher exists, closing it before opening #{hit}')
					prev.close('superseded by another target\'s destination probe')

			w = OobWindow(cpu, target, hit, entry)
			state['windows'].append(w)
			if w.wants_dest:
				state['dest_window'] = w
			print(f"[analysis1] *** TARGET HIT: {target['id']} #{hit} at "
				  f"{target['hook']} (task={w.armed_by!r}) ***")
			print(f'[analysis1]   dst=0x{dst:x} size={size}'
				  + (f' src=0x{src:x}' if src is not None else '')
				  + ' (store not yet executed)')
			log(f"{target['id']} hit #{hit}: dst=0x{dst:x} size={size}")
			w.capture(cpu, dst, size, src)
			return

	def _on_kasan_report(cpu):
		"""KASAN only calls kasan_report() when a range check has failed, so this
		is the unambiguous "the access is out of bounds" signal.

		It confirms every window that is open in the SAME task — which is how a
		hook nested inside another hook (memcpy -> kasan_check_range) gets both of
		its windows confirmed for the one access.  A report raised by anything else
		while our windows happen to be open must not confirm them, hence the task
		check.
		"""
		ctr['kasan_report'] += 1
		if not state['windows']:
			return
		# process_name() is one OSI walk; kasan_report is rare, and all open
		# windows are compared against the same answer.
		pname = process_name(panda, cpu)
		for w in list(state['windows']):
			if w.closed:
				continue
			if w.cpu_index != cpu.cpu_index or pname != w.armed_by:
				print(f'[analysis1] kasan_report in task {pname!r}, not the '
					  f'{w.armed_by!r} that opened window #{w.hit} '
					  f'({w.target["id"]}) — not confirming')
				continue
			w.note_report()

	# ------------------------------------------------------------------
	# callstack_instr hooks
	# ------------------------------------------------------------------

	def on_ret(cpu, addr):
		"""Function-return hook.  `addr` is the function that just returned
		(callstack_instr.cpp:398 passes function_stacks[i], not the return site).

		IMPORTANT: this fires from PANDA_CB_BEFORE_BLOCK_EXEC, so it must not do
		anything that could perturb the block about to execute.  Enabled-bit flips
		and Python state are fine; pm.refresh() and taint labelling are deferred
		to the on_call side."""
		if state['stopped']:
			return

		# --- window transitions ---
		# list() because finalise() removes from state['windows'].
		for w in list(state['windows']):
			if w.closed or (addr != w.hook_addr and addr != w.store_addr):
				continue
			# The hooked helper returned: report done, control back in the caller,
			# store imminent.  Tested first because for a source-only target
			# hook_addr == store_addr and wants_dest is False, in which case the
			# elif must be the branch that runs.
			if w.wants_dest and w.state == 'armed' and addr == w.hook_addr:
				if w.same_ctx(cpu):
					w.go_live()
			elif addr == w.store_addr:
				if w.same_ctx(cpu):
					w.close(f'{w.target["store_fn"]} returned')

		# --- demand-paging: remember the faulted page ---
		#
		# When the kernel services a fault for an anonymous heap/brk VMA on behalf
		# of the reproducer, the zero-initialised page is now physically backed.
		# Every byte gets a fresh taint label so that bytes the reproducer never
		# explicitly writes (i.e. they stay zero) are still tracked when they
		# reach a sink.  A later explicit store via kdo_store_callback overwrites
		# the background label with a more specific one, which is what we want.
		if handle_mm_fault_addr is None or addr != handle_mm_fault_addr:
			return

		cpu_idx = cpu.cpu_index
		fault_addr = handle_mm_fault_pending.pop(cpu_idx, None)
		if fault_addr is None:
			# We never saw the matching on_call — most likely the hook was
			# registered while the call was already in flight, or the fault was
			# re-entered recursively.
			print(f'[analysis1] on_ret(handle_mm_fault): no pending entry for '
				  f'cpu{cpu_idx}, skipping')
			return

		page_base = fault_addr & ~(PAGE_SIZE - 1)
		print(f'[analysis1] on_ret(handle_mm_fault): cpu{cpu_idx} '
			  f'fault_addr=0x{fault_addr:x} page_base=0x{page_base:x} — queued')
		# Queue the raw page base only.  The VMA lookup and heap/anon filter both
		# read guest memory, so they happen in the on_call drain.
		pending['zero_pages'].append(page_base)

	def _drain_zero_pages(cpu):
		"""Label the pages queued by on_ret.  Called from on_call
		(AFTER_BLOCK_EXEC) where pm.refresh() and taint labelling are safe."""
		# One refresh covers every queued page: they were all faulted inside the
		# same block window, so the VMA list has not changed between them.
		pm.refresh(cpu)

		while pending['zero_pages']:
			page_base = pending['zero_pages'].pop(0)

			containing_vma = None
			for mapping in pm.mappings:
				if mapping['base'] <= page_base < mapping['base'] + mapping['size']:
					containing_vma = mapping
					break

			if containing_vma is None:
				print(f'[analysis1] zero-page drain: 0x{page_base:x} not in any '
					  f'mapping ({len(pm.mappings)} entries) — skipping')
				continue
			# Deliberately narrower than ProcessMappings.is_heap(), which also
			# accepts '[stack]': the stack is written by the process itself and
			# does not need background labels.
			if containing_vma['name'] not in ('[heap]', '[anon]'):
				print(f'[analysis1] zero-page drain: 0x{page_base:x} in vma '
					  f'{containing_vma["name"]!r} — not heap/anon, skipping')
				continue

			enable_taint()
			first_label = ctr['labels']
			print(f'[analysis1] zero-page drain: labelling 0x{page_base:x} from '
				  f'label {first_label} (vma {containing_vma["name"]} '
				  f'0x{containing_vma["base"]:x}+{containing_vma["size"]})')
			untranslatable = 0
			# One page-table walk for the whole page instead of 4096.
			page_paddrs = v2p_range(cpu, page_base, PAGE_SIZE)
			for offset in range(PAGE_SIZE):
				taint_paddr = page_paddrs[offset]
				if taint_paddr is None:
					untranslatable += 1
					continue
				label_map[ctr['labels']] = {
					'virt_addr': hex(page_base + offset),
					'backtrace': [],
					'type': 'zero_page',
				}
				panda.taint_label_ram(taint_paddr, ctr['labels'])
				ctr['labels'] += 1
			last_label = ctr['labels'] - 1
			if untranslatable:
				print(f'[analysis1] zero-page drain: {untranslatable}/{PAGE_SIZE} '
					  f'bytes untranslatable for 0x{page_base:x}; labels '
					  f'{first_label}..{last_label}')
			else:
				print(f'[analysis1] zero-page drain: labelled all {PAGE_SIZE} bytes '
					  f'of 0x{page_base:x} with labels {first_label}..{last_label}')

	def _on_kdo_store_callback(cpu):
		"""void kdo_store_callback(int id, void *ptr, int len) — the reproducer
		telling us it just stored attacker-controlled bytes.  arg0=rdi (id),
		arg1=rsi (ptr), arg2=rdx (len, signed 32-bit)."""
		store_id = panda.arch.get_arg(cpu, 0)
		ptr      = panda.arch.get_arg(cpu, 1)
		length   = panda.arch.get_arg(cpu, 2)
		length   = length if length < (1 << 31) else length - (1 << 32)

		if length <= 0:
			log(f'kdo_store_cb id={store_id} ptr=0x{ptr:x} len={length} '
				f'SKIP:non-positive-len')
			return

		store_end = ptr + length

		containing = None
		for mapping in pm.mappings:
			if mapping['base'] <= ptr < mapping['base'] + mapping['size']:
				containing = mapping
				break

		heap_mapping = None
		for mapping in pm.mappings:
			mapping_end = mapping['base'] + mapping['size']
			if (ptr >= mapping['base'] and store_end <= mapping_end
					and ProcessMappings.is_heap(mapping)):
				heap_mapping = mapping
				break

		log(
			f'kdo_store_cb id={store_id} ptr=0x{ptr:x} len={length}'
			f' taint_enabled={panda.taint_enabled()}'
			+ (
				f' mapping={containing["name"]!r} 0x{containing["base"]:x}'
				f'+0x{containing["size"]:x}'
				if containing else f' mapping=NONE (total={len(pm.mappings)})'
			)
			+ (' -> WILL_TAINT' if heap_mapping else ' -> SKIP')
		)

		if heap_mapping is None:
			if containing is None:
				print(f'[analysis1] kdo_store_callback(id={store_id}, '
					  f'ptr=0x{ptr:x}, len={length}) — ptr not in any known '
					  f'mapping ({len(pm.mappings)} entries), skipping taint')
			else:
				print(f'[analysis1] kdo_store_callback(id={store_id}, '
					  f'ptr=0x{ptr:x}, len={length}) — ptr in mapping '
					  f'{containing["name"]!r} 0x{containing["base"]:x}'
					  f'+{containing["size"]} but not a heap mapping (or the '
					  f'store does not fit), skipping taint')
			return

		print(f'[analysis1] kdo_store_callback(id={store_id}, ptr=0x{ptr:x}, '
			  f'len={length}) — in heap mapping 0x{heap_mapping["base"]:x}'
			  f'+{heap_mapping["size"]}, tainting')

		# All bytes from a single kdo_store_callback call share one label, so the
		# call site is the unit of taint granularity, not the byte.
		enable_taint()
		backtrace  = [hex(a) for a in callers(cpu)]
		call_label = ctr['labels']
		ctr['labels'] += 1
		label_map[call_label] = {
			'virt_addr': hex(ptr),
			'len':       length,
			'backtrace': backtrace,
			'type':      'kdo_store',
		}
		store_paddrs   = v2p_range(cpu, ptr, length)
		untranslatable = 0
		for offset in range(length):
			taint_paddr = store_paddrs[offset]
			if taint_paddr is None:
				untranslatable += 1
				continue
			panda.taint_label_ram(taint_paddr, call_label)
		print(f'[analysis1]   tainted {length - untranslatable}/{length} bytes '
			  f'with label {call_label}')

	def _on_sink(cpu):
		"""void sink(char *ptr, int len) — reproducer-side check that the labels
		we planted actually survive to where the reproducer expects them.
		arg0=rdi (ptr), arg1=rsi (len, signed 32-bit)."""
		ptr    = panda.arch.get_arg(cpu, 0)
		length = panda.arch.get_arg(cpu, 1)
		length = length if length < (1 << 31) else length - (1 << 32)

		print(f'[analysis1] sink(ptr=0x{ptr:x}, len={length}) — checking taint')
		tainted, meta = read_taint_range(cpu, ptr, length, 'sink')
		if tainted:
			print(f'[analysis1] sink: {len(tainted)}/{meta["read"]} bytes tainted')
		else:
			print(f'[analysis1] sink: no taint on sink bytes '
				  f'(ptr=0x{ptr:x}, len={length})')

		analysis['sink'] = {
			'ptr': hex(ptr),
			'len': length,
			'tainted_bytes': tainted,
			'meta': meta,
		}
		_write_analysis()
		# Same reasoning as a finalised violation: end_analysis() only queues the
		# stop, so go inert too or later hooks will act on a half-stopped replay.
		state['stopped'] = True
		panda.end_analysis()

	def on_call(cpu, addr):
		"""Call hook.  Fires from PANDA_CB_AFTER_BLOCK_EXEC for EVERY call
		instruction in the guest, so everything before the first `return` has to
		be cheap and free of guest reads."""
		if state['stopped']:
			return

		# 1. Catalogue hooks.  Dict lookup, then integer comparisons on the call
		#    stack; only a matching pedigree gets as far as an OSI walk.
		tlist = hook_targets.get(addr)
		if tlist is not None:
			_on_hook_call(cpu, addr, tlist)
			return

		# 2. The out-of-bounds signal.  No task filter here — the window itself
		#    checks that the report fired in the task that opened it.
		if addr == kasan_report_addr:
			_on_kasan_report(cpu)
			return

		# 3. Terminal condition, also unfiltered: a panic in ANY task ends the
		#    replay, and the p9-style bugs run in a kworker, not the reproducer.
		if addr == panic_addr:
			log('PANIC!')
			print(f'[analysis1] PANIC reached — target hits so far: '
				  f'{dict(ctr["target_hits"])}')
			analysis['panicked'] = True
			_write_analysis()
			state['stopped'] = True
			panda.end_analysis()
			return

		# 4. Everything else is reproducer-side.  Reject cheaply first; the
		#    pending drains have to get through too, hence the second clause.
		if addr not in interesting_call_addrs and not (
				pending['refresh'] or pending['zero_pages']):
			return
		if not _in_repro(cpu):
			return

		# Drain a deferred pm.refresh() requested by an mmap/brk return.  on_call
		# fires from AFTER_BLOCK_EXEC, so the first user-space block after the
		# syscall return has already run: the kernel's maple-tree rewrite is
		# complete and the tree is stable to read.
		if pending['refresh']:
			pending['refresh'] = False
			pm.refresh(cpu)

		if pending['zero_pages']:
			_drain_zero_pages(cpu)

		if addr == handle_mm_fault_addr:
			# handle_mm_fault(vma, address, flags, regs): arg1=rsi is the address
			fault_addr = panda.arch.get_arg(cpu, 1)
			handle_mm_fault_pending[cpu.cpu_index] = fault_addr
			print(f'[analysis1] on_call(handle_mm_fault): cpu{cpu.cpu_index} '
				  f'address=0x{fault_addr:x}')
			return

		if addr == kdo_store_cb_addr:
			_on_kdo_store_callback(cpu)
			return

		if addr == sink_addr:
			_on_sink(cpu)
			return

	# ------------------------------------------------------------------
	# syscalls2 hooks
	# ------------------------------------------------------------------

	@panda.ppp("syscalls2", "on_sys_execve_enter")
	def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
		try:
			fname_bytes = panda.virtual_memory_read(cpu, fname_ptr, 256)
		except Exception:
			print("[analysis1] warning: could not read execve fname")
			return
		fname = fname_bytes.split(b'\x00', 1)[0].decode('utf-8', 'ignore')

		if not repro_pattern.search(fname):
			return

		print(f"[analysis1] repro execve detected: {fname} — enabling call hooks "
			  f"and the after-insn gate")
		panda.ppp("callstack_instr", "on_call")(on_call)
		panda.ppp("callstack_instr", "on_ret")(on_ret)

		# One-time, translation-affecting setup, done here in user context so that
		# nothing on the kernel path around the OOB store has to change how code
		# is generated:
		#   - enable_memcb() is set once and never toggled.  It is inert on the
		#     LLVM path taint2 forces (tcg-llvm always emits the _panda store
		#     helpers) but flipping it mid-replay would change helper selection
		#     for subsequently translated blocks.
		#   - the after_insn_translate gate is consulted at TRANSLATE time, and
		#     panda_enable_callback() does not flush (panda/src/callbacks.c:699),
		#     so already-translated blocks would carry no probe without a flush.
		#     panda_do_flush_tb() only sets a flag, honoured at the next TB lookup
		#     in before_find_fast() (panda/src/cb-support.c:215), so it is safe
		#     from a callback.
		# The gate then stays on for the rest of the replay so the helper is
		# re-emitted on every retranslation — including taint2's own flush when
		# taint_enable() switches to LLVM.  The probe and the watcher are left
		# disabled and armed per window; both are plain enabled-bit flips.
		panda.enable_memcb()
		panda.enable_callback('oob_probe_gate')
		panda.flush_tb()
		panda.disable_ppp("on_sys_execve_enter")

	@panda.ppp("syscalls2", "on_sys_mmap_enter")
	def on_sys_mmap_enter(cpu, pc, addr_hint, length, prot, flags, fd, offset):
		if not _in_repro(cpu):
			return
		print(
			f'[analysis1] mmap enter: hint=0x{addr_hint:x} len=0x{length:x} '
			f'prot=0x{prot:x} flags=0x{flags:x} fd={fd} offset=0x{offset:x}'
		)

	@panda.ppp("syscalls2", "on_sys_mmap_return")
	def on_sys_mmap_return(cpu, pc, addr_hint, length, prot, flags, fd, offset):
		if not _in_repro(cpu):
			return
		ret = panda.arch.get_retval(cpu)
		print(
			f'[analysis1] mmap return: addr=0x{ret:x} '
			f'(hint=0x{addr_hint:x} len=0x{length:x} '
			f'prot=0x{prot:x} flags=0x{flags:x} fd={fd} offset=0x{offset:x})'
		)
		# Don't refresh here — the kernel's maple-tree rewrite may not be fully
		# committed at the syscall-return boundary.  Flag it so on_call refreshes
		# on the next user-space block instead.
		pending['refresh'] = True

	@panda.ppp("syscalls2", "on_sys_brk_return")
	def on_sys_brk_return(cpu, pc, brk):
		if not _in_repro(cpu):
			return
		ret = panda.arch.get_retval(cpu)
		print(f'[analysis1] brk return: new_brk=0x{ret:x} (requested=0x{brk:x})')
		# Same reasoning as mmap: defer the refresh to on_call.
		pending['refresh'] = True

	# ------------------------------------------------------------------
	# Run
	# ------------------------------------------------------------------

	print(f'[analysis1] replay start: record={record} '
		  f'(stop_on_first_violation={stop_on_first_violation})')
	try:
		panda.run_replay(record)
	except Exception:
		# Catches Python-level failures anywhere in the analysis so the summary
		# and the consolidated JSON below still get produced.  It canNOT catch the
		# SIGABRT this recording ends in — see _write_analysis() — which is why
		# every observation is flushed as it is finalised.
		print("[analysis1] caught exception during replay")
		print(traceback.format_exc())
	finally:
		# Any window still open at the end of the replay has to be closed, or its
		# evidence is silently dropped.
		for w in list(state['windows']):
			if not w.closed:
				w.close('replay ended with the window still open')

		outfile.close()
		print('[analysis1] replay done!')

		end = time.time()
		print(f'[analysis1] time: {end - start:.1f}s')
		for hook, n in sorted(ctr['hook_calls'].items()):
			print(f'[analysis1] {hook} calls seen (all tasks): {n}')
		for target in targets:
			tid  = target['id']
			hits = ctr['target_hits'].get(tid, 0)
			obs  = [o for o in analysis.get('observations', [])
					if o['target'] == tid]
			print(f'[analysis1] {tid}: {hits} pedigree-matching hit(s), '
				  f'outcomes={[o["outcome"] for o in obs]}')
		print(f'[analysis1] kasan_report calls: {ctr["kasan_report"]}')
		print(f'[analysis1] OOB writes confirmed tainted: '
			  f'{sum(1 for o in analysis.get("observations", []) if o["outcome"] == "tainted")}'
			  f'/{len(analysis.get("observations", []))} observation(s)')
		print(f'[analysis1] cached process mappings: {len(pm.mappings)}')
		print(f'[analysis1] total taint labels created: {ctr["labels"] - 1}')

		analysis['replay_time'] = end - start
		_write_analysis()


def replay(rootfs, kernel, enable_logging=True, record='record',
		   stop_on_first_violation=True):
	"""stop_on_first_violation:
	  True  (default) — return as soon as one OOB write is confirmed tainted.
	                    Exits cleanly.
	  False           — run to the end of the analysis, collecting every
	                    violation.  This recording then dies of SIGABRT at its
	                    desync point, so rrr will raise "Replay failed -6" even
	                    though analysis1.json holds every observation collected up
	                    to that point (it is rewritten after each one)."""
	print("starting")
	rrr.replay(rootfs, kernel, record, __replay,
			   additional_args=[enable_logging, stop_on_first_violation])
