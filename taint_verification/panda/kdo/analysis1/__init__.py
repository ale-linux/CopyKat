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

Three shapes are handled, described declaratively in BUG_CATALOGUE.  The first two
differ in what the hooked function's arguments give us:

  * `source: True` — the hooked function is handed the source buffer, so the
    taint can be read straight away, before anything stores.  This is the
    preferred shape and it is worth going out of the way to get it: pick a hook
    whose arguments include the source, even if that is one frame further out
    than the KASAN helper the report happens to name.  __asan_memcpy(dst,src,n)
    and memcpy(dst,src,n) both qualify.
  * `dest: True` — only a destination and a size are available
    (__kasan_check_write(ptr,n), kasan_check_range(ptr,n,write,ip)).  We then have
    to wait for the store to land and read the taint on the destination bytes.
    That is a lot more machinery, and it fails outright when the caller acts on
    the check's return value — see "GETTING THE STORE TO EXECUTE".

Reading the source is only equivalent to reading the destination when the store
is a verbatim copy, which is exactly the mem*() case: taint2 propagates labels
byte-for-byte through the store, so src[0..n) carries the labels post-store
dst[0..n) would.  For memset, computed values or partial writes it is not, and
the destination probe is the only correct answer.

Neither shape may assume the reproducer is `current`: the p9_read_work bug
executes entirely inside a kernel worker thread.

THE THIRD SHAPE: THE REPORT CALL ITSELF IS THE HOOK  (`confirm: 'hook'`)
------------------------------------------------------------------------
Both shapes above assume there IS a KASAN helper between the faulting function and
the report — something whose arguments describe the access.  With
CONFIG_KASAN_INLINE there is not.  The shadow test is open-coded into the
instrumented function and the only call left on the failure path is the report
thunk, so the report reads:

    kasan_report+0xca/0x100
    fuse_dev_do_write+0x3088/0x30b0      <- Write of size 4 at ffff888012f726dc
    fuse_dev_write+0x144/0x1e0

No __asan_store4, no kasan_check_range, no __kasan_check_write frame to hook.  The
access is described by the report call itself, so that call becomes the hook:
`__asan_report_store4_noabort(void *addr)` gives the target in rdi and the width in
its own name (hence `args: 'ptr'` + `access_size`); `kasan_report(addr, size,
is_write, ip)` would give all three in registers.

Such a hook is its OWN discriminator.  Everything under CONFIRMATION below exists
because a KASAN helper is called for in-bounds accesses too and only kasan_report
tells the two apart — but a report thunk is reached ONLY when a shadow check has
already failed.  So `confirm: 'hook'` means "the pedigree match IS the
confirmation": the window is confirmed at hook entry from the hook's own
arguments, with no second event to wait for.

Hook the THUNK, not kasan_report.  Hooking kasan_report directly is the obvious
reading of that report and it would never fire, because

    void __asan_report_store4_noabort(void *addr)
    { kasan_report(addr, 4, true, _RET_IP_); }        /* mm/kasan/generic.c */

discards the result, so the compiler emits `jmp kasan_report` rather than a call.
Two independent signs of it: the report's own stack trace has NO
__asan_report_store4_noabort frame between kasan_report and fuse_dev_do_write,
which a real call would have left for the ORC unwinder to print; and
callstack_instr only pushes a frame when a translation block ENDS IN A CALL
(callstack_instr.cpp:449-462), so a tail jump into kasan_report produces no
on_call(kasan_report) at all — the arrival that this module's confirmation path
and `hook_targets` dispatch both key on.  Hooking the thunk is correct either way,
since the compiler always reaches it with a real call, and it is the better
pedigree anchor too: callers[0] is then exactly the `fuse_dev_do_write+0x3088` the
report prints.  (`kasan_report` is still supported as a hook — on_call() falls
through to the confirmation path when an entry claims it — and BUG_CATALOGUE keeps
a commented-out entry for the kernel where the thunk is absent or not tail-called.)

The rest of the machinery needs nothing new, which is worth spelling out because
none of it is obvious:

  * ARMING.  on_ret reports the function the CALL entered, i.e. function_stacks[i]
    (callstack_instr.cpp:398), so the `ret` that physically sits inside
    kasan_report fires on_ret(__asan_report_store4_noabort) — matching the hook
    address, tail call or not.  The write watcher goes live there, exactly as it
    does for __kasan_check_write.
  * THE STORE EXECUTES on a stock kernel.  The thunk returns void and the
    instrumented code acts on nothing, so there is no veto — the same reason the
    bitmap_ip_add entry works unpatched, and the reason this shape needs neither
    kernel-patches/0001-* nor kasan_multi_shot.  See "GETTING THE STORE TO
    EXECUTE".
  * THE STORE IS NOT AT THE RETURN ADDRESS.  With inline instrumentation the
    report call lives in a cold block near the end of the function (0x3088 of
    0x30b0) and jumps back to the hot path, so the store executes some distance
    away.  The watcher is keyed on dst and the after_insn gate is unconditional,
    which is precisely what makes that a non-issue — see "COST".

PRUNING
-------
These helpers are called millions of times per second of guest time.  A hit only
counts when the *call stack* matches the one in the KASAN report — that is the
`pedigree` field of a catalogue entry, and it is checked with pure integer
comparisons before anything touches guest memory.

CONFIRMATION
------------
All of this is about a hook that is also called for in-bounds accesses, i.e.
`confirm: 'kasan_report'`.  A hook that only exists on the failure path confirms
itself and skips the whole dance — see "THE THIRD SHAPE" above.

A matching call stack is necessary but not sufficient: the same call site is hit
many times and only one of those calls is the out-of-bounds one.  kasan_report()
is the discriminator — KASAN only calls it when a range check has actually
failed.  So every matching hit opens a *window*, and a reading is only promoted
to a violation if kasan_report() fired while that window was open AND named the
access the window captured (OobWindow.report_matches: the reported range must
overlap the range we recorded).  That range test is what keeps a report raised for
something else from confirming the window — including memcpy's other check, the
read of src, whose range lies in a different object.  The report's is_write flag is
recorded but not gated on; every catalogue entry is a write that fails on the
destination, so it would add nothing the range test does not already give.

The report's own (addr, size, is_write, ip) are recorded alongside the verdict, so
"is this the hit the KASAN report is about?" is answered by the JSON rather than
by eye.

Either order works.  A destination window is confirmed before its reading exists
(the report runs inside the check; the store comes later).  A source window is
confirmed after its reading could have been taken — and in fact the source read is
deferred until confirmation, since nothing between the hook's entry and its range
check writes to the source buffer, and the many in-bounds hits then cost no taint
scan at all.  Where hook and store_fn are the same function (memcpy) the window
spans exactly one call, so the confirming report can only be the one that call
raised: there is no cross-call staleness to reason about.

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
This whole section is about the mem*() family and nothing else.  Every OTHER
destination target — compiler-generated __asan_store*()/__asan_report_store*(),
instrument_write(), __kasan_check_write() — discards the check's result, so its
store executes on a stock kernel with no patch and no boot parameter.  That covers
the bitmap_ip_add and fuse_dev_do_write entries.

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
  2. Read the SOURCE instead, and never depend on the store.  THIS IS WHAT THE
     p9_read_work ENTRY DOES, and it is the right default wherever the source is
     reachable.  The report's faulting frame is a `call memcpy`, so hooking memcpy
     itself hands you (dest, src, len) in rdi/rsi/rdx and the taint on the bytes
     about to go out of bounds is readable before anything stores.  Works on the
     recordings you already have, needs no kernel change, and for a verbatim copy
     it is not a proxy for the destination reading but the same answer (see the
     note under "Two shapes" above).  It stops being equivalent only where the
     store is not a verbatim copy — memset, computed values, partial writes — and
     there the destination probe is the only correct route.
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
#               'ptr'            (ptr)                   rdi     — width is not
#                        an argument at all, it is in the hook's NAME
#                        (__asan_report_store4_noabort), so `access_size` supplies
#                        it.  The variable-width sibling
#                        __asan_report_store_n_noabort(addr, size) is 'ptr_size'.
#   access_size  the access width in bytes.  REQUIRED for args=='ptr', ignored
#             otherwise.  Comes from the report's "Write of size N".
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
#   confirm   what promotes a pedigree-matching hit to a real out-of-bounds
#             access:
#               'kasan_report'  wait for a kasan_report() call in the same task
#                        that names an overlapping range.  For a hook KASAN also
#                        calls on in-bounds accesses, which is most of them.
#               'hook'   the hook itself only exists on the failure path
#                        (__asan_report_store*_noabort, kasan_report), so the
#                        pedigree match IS the confirmation and the window is
#                        confirmed at entry from the hook's own arguments.  See
#                        "THE THIRD SHAPE" in the module docstring.
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
		'confirm':  'kasan_report',
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
		'confirm':  'kasan_report',
	},
	{
		# The report's faulting frame is `_copy_to_iter+0x997`, i.e. a `call
		# memcpy`, so hook memcpy itself rather than the kasan_check_range it
		# calls.  rdi/rsi/rdx then hold (dest, src, len) and the taint on the
		# bytes about to go out of bounds is readable with no store required —
		# which matters, because on a stock kernel that store never happens: the
		# wrapper is
		#     if (!kasan_check_range(src,  len, false, _RET_IP_) ||
		#         !kasan_check_range(dest, len, true,  _RET_IP_))
		#             return NULL;
		#     return __memcpy(dest, src, len);
		# and kasan_check_range() returns `!kasan_report(...)`, so a check whose
		# report is PRINTED vetoes the copy.  See "GETTING THE STORE TO EXECUTE".
		#
		# This is sound for a memcpy specifically because taint2 copies labels
		# byte-for-byte through the store, so src[0..len) carries exactly the
		# labels post-store dest[0..len) would.  It is NOT a general substitute:
		# for memset, computed values or partial writes the source is not the
		# thing that lands.
		#
		# Window scoping falls out for free: hook == store_fn == memcpy, so the
		# window is open for exactly the duration of one memcpy call.  The
		# kasan_report that confirms it can therefore only be the one raised by
		# that call's own range check — there is no cross-call staleness to worry
		# about, which is stronger than "keep the most recent reading".
		'id':       'p9_read_work',
		'hook':     'memcpy',
		'args':     'memcpy',
		# memcpy is one of the hottest functions in the kernel and
		# _copy_to_iter+0x997 alone would match every pipe/socket read through
		# that call site, so keep p9_read_work+0x1f0 in the pedigree to prune.
		# Frame layout at memcpy entry:
		#   [0] _copy_to_iter+0x997     the return address the report prints
		#   [1] copy_page_to_iter+...
		#   [2] pipe_read+...
		#   [3] __kernel_read+...
		#   [4] kernel_read+...
		#   [5] p9_read_work+0x1f0
		'pedigree': (('frame', 0, ('_copy_to_iter',), 0x997),
					 ('anywhere', ('p9_read_work',), 0x1f0)),
		'store_fn': 'memcpy',
		'ctx':      'kworker',
		'source':   True,
		'dest':     False,
		'confirm':  'kasan_report',
	},
	{
		# CONFIG_KASAN_INLINE: the shadow check is open-coded into
		# fuse_dev_do_write and the only call left on the failure path is the
		# report thunk, so the report has no KASAN-helper frame to hook —
		#     kasan_report+0xca/0x100
		#     fuse_dev_do_write+0x3088/0x30b0    Write of size 4 at ffff888012f726dc
		#     fuse_dev_write+0x144/0x1e0
		# The thunk IS the hook, and because it only exists on the failure path it
		# confirms itself (confirm='hook').  See "THE THIRD SHAPE" in the module
		# docstring for why this is the thunk rather than kasan_report — the thunk
		# tail-jumps into kasan_report, so on_call(kasan_report) never fires — and
		# for why the store executes here on a stock kernel while memcpy's does
		# not.
		#
		# dest-only, and not because a source is merely inconvenient: the store is
		# a computed 4-byte value with no source buffer anywhere.  This is exactly
		# the case the note under "Two shapes" reserves for the destination probe.
		'id':          'fuse_dev_do_write',
		'hook':        '__asan_report_store4_noabort',
		'args':        'ptr',
		'access_size': 4,          # the '4' in the hook's name; "Write of size 4"
		# callers[0] at thunk entry is the return address of the `call` the
		# compiler emitted, which is precisely what the report prints.  Frame 1 is
		# fuse_dev_write+0x144; not enforced, because one instruction in a cold
		# report block is already unique and the thunk is ice cold — it is only
		# ever called on a failed check, so there is no hot path to prune.
		'pedigree':    (('frame', 0, ('fuse_dev_do_write',), 0x3088),),
		'store_fn':    'fuse_dev_do_write',
		'ctx':         'repro',
		'source':      False,
		'dest':        True,
		'confirm':     'hook',
	},
	# Fallback for the same bug, hooking kasan_report directly.  Usable only on a
	# kernel where __asan_report_store4_noabort is absent (outline instrumentation)
	# or where it reaches kasan_report by a real CALL rather than a tail jump.  On
	# this one it tail-jumps, so on_call never sees kasan_report at all and this
	# entry would resolve, report itself available, and silently never hit — which
	# is exactly the failure mode to watch for.  Enable it INSTEAD of the
	# entry above, not alongside: both are destination targets, there is a single
	# watcher/probe pair, and the later window would close the earlier one as
	# 'store_never_executed'.
	#
	# {
	# 	'id':       'fuse_dev_do_write_report',
	# 	'hook':     'kasan_report',
	# 	'args':     'ptr_size_write',
	# 	# 'anywhere' rather than 'frame': the frame index depends on whether the
	# 	# thunk left a frame, which is the very thing in doubt here.
	# 	'pedigree': (('anywhere', ('fuse_dev_do_write',), 0x3088),),
	# 	'store_fn': 'fuse_dev_do_write',
	# 	'ctx':      'repro',
	# 	'source':   False,
	# 	'dest':     True,
	# 	'confirm':  'hook',
	# },
	# Retired: the same bug via the kasan_check_range inside memcpy, watching the
	# destination for the store.  It cannot produce a reading on a stock kernel —
	# the check it hooks is the very one whose failure makes memcpy return NULL —
	# so it only ever reported 'store_never_executed' while costing a window, an
	# OSI walk and a destination paddr resolution per matching p9 message.  Kept
	# here because it DOES work on a kernel patched per kernel-patches/0001-*, or
	# on any occurrence whose report is suppressed, where it corroborates the
	# source reading against the bytes that actually landed.  Re-enable both
	# together; the machinery supports concurrent windows and kasan_report
	# confirms all of them.
	#
	# {
	# 	'id':       'p9_read_work_dest',
	# 	'hook':     'kasan_check_range',
	# 	'args':     'ptr_size_write',
	# 	'pedigree': (('frame', 1, ('_copy_to_iter',), 0x997),
	# 				 ('anywhere', ('p9_read_work',), 0x1f0)),
	# 	'store_fn': 'memcpy',
	# 	'ctx':      'kworker',
	# 	'source':   False,
	# 	'dest':     True,
	# 	'confirm':  'kasan_report',
	# },
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

# Debug: ALSO read the source taint at hook entry, not only when kasan_report
# confirms the window.  Never authoritative — the deferred read stays the one that
# produces the verdict — but useful for two things:
#   * it shows the labels on hits that never get confirmed, which is how you tell
#     "the source is never tainted" apart from "we never reached the OOB call";
#   * _read_source_taint() diffs the two readings and complains if they differ,
#     which is the empirical check on the assumption that makes deferring sound
#     (nothing writes the source buffer between the hook's entry and its range
#     check).  Leave it on until you trust that, then turn it off.  On a
#     disagreement the DEFERRED read stays authoritative — it is the later of the
#     two and therefore the closer approximation to what __memcpy will copy — and
#     reading['disagrees_with_hook_entry'] records what moved.
# The block also hexdumps the source bytes themselves, annotated with which of
# them carry labels — the two questions "is the OOB data attacker-controlled" and
# "is it the data I put there" are usually asked together, and the values answer
# the second one directly.
# Costs one taint scan plus one guest read per pedigree-matching hit, i.e. exactly
# what deferring was meant to avoid, so turn it off for a long run or a hot
# pedigree.
DEBUG_EAGER_SOURCE_READ = True

# How many source bytes the debug block dumps and stores in analysis1.json.  A
# p9 message or a URB can be kilobytes; a hexdump of that per hit is unreadable
# and the JSON grows by 2 hex chars per byte per hit.
DEBUG_DUMP_MAX_BYTES = 128

# Kernel text on x86_64 with nokaslr.  Used to disambiguate symbols that exist
# in both vmlinux and the statically-linked reproducer ('memcpy' is the one that
# bites: rrr's symbol_map is last-writer-wins, so the userspace entry clobbers
# the kernel one).
KERNEL_TEXT_MIN = 0xffffffff00000000


def _read_guest_bytes(panda, cpu, base, length):
	"""Best-effort guest read of [base, base+length).

	One panda_virtual_memory_rw() per PAGE rather than one call for the whole
	range, so a single unmapped page costs that page and not the entire dump.
	Returns (data, missing) where data is `length` bytes with 0 substituted for
	anything unreadable, and missing is the set of offsets that were substituted.
	"""
	data = bytearray(length)
	missing = set()
	off = 0
	while off < length:
		va = base + off
		chunk = min(PAGE_SIZE - (va & (PAGE_SIZE - 1)), length - off)
		try:
			raw = panda.virtual_memory_read(cpu, va, chunk)
			data[off:off + chunk] = bytes(raw)
		except Exception:
			missing.update(range(off, off + chunk))
		off += chunk
	return bytes(data), missing


def _hexdump(data, tainted=frozenset(), missing=frozenset(), width=16):
	"""Hexdump lines, with a mask row under any line that has labelled bytes.

	Each byte occupies a fixed 3-character cell so the mask lines up under the
	values: `TT` for a byte carrying taint labels, `--` for one that does not, and
	`??` in the value row for a byte that could not be read out of the guest."""
	out = []
	for off in range(0, len(data), width):
		chunk = data[off:off + width]
		cells = ''.join('?? ' if (off + i) in missing else f'{b:02x} '
						for i, b in enumerate(chunk))
		asc = ''.join('?' if (off + i) in missing
					  else (chr(b) if 32 <= b < 127 else '.')
					  for i, b in enumerate(chunk))
		out.append(f'{off:04x}  {cells:<{width * 3}} |{asc}|')
		if any((off + i) in tainted for i in range(len(chunk))):
			mask = ''.join('TT ' if (off + i) in tainted else '-- '
						   for i in range(len(chunk)))
			out.append(f'      {mask:<{width * 3}} (taint)')
	return out


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

		# Catalogue self-consistency.  Reported the same way as a missing symbol so
		# that a malformed entry disables its own target and says why, rather than
		# raising out of a callback in the middle of a replay.
		if t['confirm'] not in ('kasan_report', 'hook'):
			return None, f"unknown confirm mode {t['confirm']!r}"
		if t['args'] == 'ptr' and not t.get('access_size'):
			return None, "args 'ptr' needs a positive access_size"

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
			'confirm':   entry['confirm'],
			'evidence':  ([] + (['source'] if entry['source'] else [])
							 + (['dest'] if entry['dest'] else [])),
		}
		print(f"[analysis1] target {entry['id']!r}: hook="
			  f"{entry['hook']}@0x{resolved['hook_addr']:x} "
			  f"store_fn={entry['store_fn']}@0x{resolved['store_addr']:x} "
			  f"ctx={entry['ctx']} confirm={entry['confirm']} "
			  f"pedigree={pedigree_desc}")

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
	# Maps any address returned by mmap/brk -> backtrace list captured at that
	# syscall return.  At zero-page drain time, the containing VMA is looked up
	# and the first backtrace whose key falls within the VMA range is attached to
	# the label, giving us the syscall origin for unwritten (zero) heap bytes.
	vma_backtraces: dict[int, list] = {}

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
					 'instr_at_open', 'report', 'report_exact', 'debug_reading')

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
			self.debug_reading = None   # DEBUG_EAGER_SOURCE_READ, off the verdict path
			self.confirmed  = False
			self.report     = None      # the kasan_report() call that confirmed us
			self.report_exact = None    # did it name exactly the range we captured?
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
				self.entry['src'] = hex(src)
				# The source taint is read LAZILY, when kasan_report confirms this
				# window — not here.  Between hook entry and that report the only
				# code that has run is kasan_check_range's shadow lookups, which
				# write nothing, so the answer is identical; and the (many) hits
				# that turn out to be in-bounds then cost no taint scan at all.
				# That matters because a pedigree anchored on a hot function can
				# match hundreds of times before the OOB one.
				print(f'[analysis1]   source buffer 0x{src:x}+{size} recorded; '
					  f'taint read deferred to kasan_report')
				if DEBUG_EAGER_SOURCE_READ:
					tainted, meta = read_taint_range(cpu, src, size, 'src@entry')
					self.debug_reading = {
						'kind': 'source@entry', 'base': hex(src),
						'tainted_bytes': tainted, 'meta': meta,
					}
					if tainted:
						offs = sorted(tainted)
						print(f'[analysis1]   [debug] source taint AT HOOK ENTRY: '
							  f'{len(tainted)}/{meta["read"]} byte(s) carry labels, '
							  f'offsets={offs if len(offs) <= 24 else offs[:24] + ["..."]}')
						for off in offs[:8]:
							print(f'[analysis1]   [debug]   src@entry[{off}] '
								  f'labels={tainted[off]["labels"]} '
								  f'resolved={tainted[off]["resolved"]}')
						if len(offs) > 8:
							print(f'[analysis1]   [debug]   ... and '
								  f'{len(offs) - 8} more tainted byte(s)')
					else:
						print(f'[analysis1]   [debug] source taint AT HOOK ENTRY: '
							  f'none of {meta["read"]} byte(s) carry labels '
							  f'(untranslatable={meta["untranslatable"]}, '
							  f'taint_enabled={meta["taint_enabled"]})')

					# ...and the bytes themselves.  Safe here: capture() runs from
					# on_call, i.e. AFTER_BLOCK_EXEC, the same callback side that
					# already does the VMA walk.  The copy has not run yet, so this
					# is exactly what is about to be written out of bounds.
					dump_len = min(meta['read'], DEBUG_DUMP_MAX_BYTES)
					value, gaps = _read_guest_bytes(panda, cpu, src, dump_len)
					self.debug_reading['value'] = value.hex()
					self.debug_reading['value_unreadable_offsets'] = sorted(gaps)
					print(f'[analysis1]   [debug] source bytes about to be written '
						  f'(0x{src:x}, {dump_len} of {size})'
						  + (f', {len(gaps)} unreadable' if gaps else '')
						  + (' [truncated]' if dump_len < meta['read'] else '') + ':')
					for line in _hexdump(value, set(tainted), gaps):
						print(f'[analysis1]   [debug]   {line}')

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

		@staticmethod
		def _label_shape(reading):
			"""offset -> sorted label list, for comparing two readings."""
			return {off: sorted(info['labels'])
					for off, info in reading['tainted_bytes'].items()}

		def _read_source_taint(self, cpu):
			"""Read taint on the source buffer.  Safe to defer to confirmation
			time: nothing between the hook's entry and its range check writes to
			src, and the copy itself has not run yet."""
			tainted, meta = read_taint_range(cpu, self.src, self.req_size, 'src')
			self.reading = {'kind': 'source', 'base': hex(self.src),
							'tainted_bytes': tainted, 'meta': meta}
			if tainted:
				print(f'[analysis1]   source taint: {len(tainted)}/{meta["read"]} '
					  f'bytes at 0x{self.src:x} carry labels')
			else:
				print(f'[analysis1]   source taint: none on 0x{self.src:x}+'
					  f'{meta["read"]}')

			# The whole point of the eager debug read: check that deferring did not
			# change the answer.  If these ever disagree, something between the
			# hook's entry and its range check DID touch the source buffer and the
			# deferral is not sound for that hook — the entry reading is the one to
			# trust, because it is the one taken before anything else ran.
			if self.debug_reading is None:
				return
			at_entry = self._label_shape(self.debug_reading)
			at_report = self._label_shape(self.reading)
			if at_entry == at_report:
				print(f'[analysis1]   [debug] deferred read agrees with the hook-entry '
					  f'read ({len(at_report)} tainted byte(s)) — deferral sound here')
				return
			gained = sorted(set(at_report) - set(at_entry))
			lost   = sorted(set(at_entry) - set(at_report))
			changed = sorted(o for o in set(at_entry) & set(at_report)
							 if at_entry[o] != at_report[o])
			print(f'[analysis1]   [debug] *** WARNING: the deferred read DISAGREES '
				  f'with the hook-entry read — the source buffer changed between '
				  f'{self.target["hook"]} entry and kasan_report ***')
			print(f'[analysis1]   [debug]   gained taint at offsets {gained}')
			print(f'[analysis1]   [debug]   lost taint at offsets   {lost}')
			print(f'[analysis1]   [debug]   different labels at     {changed}')
			# The deferred read stays authoritative: the bytes that actually get
			# copied are the ones present when __memcpy runs, which is LATER than
			# either read, so the later of the two is the closer approximation.
			# Both readings are in the JSON; this flag says they did not agree.
			print(f'[analysis1]   [debug]   keeping the deferred reading (closer in '
				  f'time to the copy); both are recorded in analysis1.json')
			self.reading['disagrees_with_hook_entry'] = {
				'gained': gained, 'lost': lost, 'changed': changed,
			}

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

		def report_matches(self, report):
			"""Is this kasan_report() about the access this window captured?

			kasan_report() is handed the same (addr, size) that kasan_check_range()
			got, so for an access flagged through our hook the reported range IS the
			range we recorded.  Checked rather than assumed so that a report raised
			anywhere else in this task, while our window happens to be open, cannot
			confirm it.

			That also covers memcpy's OTHER check -- the read of src -- for free: src
			is a different object, so its range does not overlap dest's and the report
			is rejected.  report['is_write'] is therefore recorded but NOT gated on;
			every bug in BUG_CATALOGUE is an out-of-bounds write that fails on the
			destination, so the flag would add nothing the range test does not already
			give.

			Overlap rather than equality, so a KASAN version that narrows the reported
			range to the first bad byte still matches; exactness is recorded separately
			and is what you diff against the report text."""
			if self.dst is None:
				return False, 'no destination captured for this window'
			lo, hi = self.dst, self.dst + max(self.req_size, 1)
			rlo, rhi = report['addr'], report['addr'] + max(report['size'], 1)
			if rhi <= lo or rlo >= hi:
				return False, (f'reported range 0x{rlo:x}+{report["size"]} does '
							   f'not overlap the captured 0x{lo:x}+{self.req_size}')
			return True, None

		def note_report(self, cpu, report):
			"""The access really is out of bounds.

			Either kasan_report() ran while this window was open and named an
			access this window is about (confirm='kasan_report'), or the hook is
			itself on KASAN's failure path and _on_hook_call synthesised the record
			from its arguments (confirm='hook', report['via'] == 'hook')."""
			if self.confirmed or self.closed:
				return
			self.report = report
			self.report_exact = (report['addr'] == self.dst
								 and report['size'] == self.req_size)
			self.confirmed = True
			what = ('reaching ' + self.target['hook'] if report.get('via') == 'hook'
					else 'kasan_report')
			print(f'[analysis1] {what} confirms window #{self.hit} '
				  f'({self.target["id"]}) — write of size {report["size"]} at '
				  f'0x{report["addr"]:x}, ip=0x{report["ip"]:x}'
				  + ('' if self.report_exact else
					 f' (NB does not exactly match the captured '
					 f'0x{self.dst:x}+{self.req_size})'))
			# Source targets read here rather than at hook entry — see capture().
			if (self.target['source'] and self.reading is None
					and self.src is not None):
				self._read_source_taint(cpu)
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
			meta = self.reading['meta']
			if not meta['taint_enabled']:
				return 'taint_off'
			if self.reading['tainted_bytes']:
				return 'tainted'
			if meta['read'] and meta['untranslatable'] == meta['read']:
				# Every byte we tried to look at was unmapped.  Absence of labels
				# there says nothing at all.
				return 'unreadable'
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
				# How the confirmation was obtained: 'kasan_report' if an actual
				# call to it was observed, 'hook' if the hook is itself on KASAN's
				# failure path so reaching it was the report (see "THE THIRD
				# SHAPE").  Kept out of the 'kasan_report' sub-dict below, which
				# stays exactly the four arguments the report was handed.
				'confirmed_via': (None if self.report is None
								  else self.report.get('via', 'kasan_report')),
				'dst':      hex(self.dst) if self.dst is not None else None,
				'size':     self.req_size,
				'watch_size': self.watch_size,
				'stores_seen': self.store_count,
				'first_store_pc':  hex(self.first_store_pc) if self.first_store_pc is not None else None,
				'first_store_val': hex(self.first_store_val) if self.first_store_val is not None else None,
				'last_store_pc':   hex(self.last_store_pc) if self.last_store_pc is not None else None,
				'last_store_val':  hex(self.last_store_val) if self.last_store_val is not None else None,
				'guest_instrs': panda.rr_get_guest_instr_count() - self.instr_at_open,
				# The confirming kasan_report()'s own arguments, so the analysis's
				# idea of the access can be diffed against the report text without
				# reading it by eye: 'write of size <size> at addr <addr>'.
				'kasan_report': (None if self.report is None else {
					'addr':     hex(self.report['addr']),
					'size':     self.report['size'],
					'is_write': self.report['is_write'],
					'ip':       hex(self.report['ip']),
					'exact_match': self.report_exact,
				}),
				'reading':  self.reading,
				# DEBUG_EAGER_SOURCE_READ only.  Kept compact when it found nothing
				# so that a run with many in-bounds hits does not bloat the JSON.
				'source_reading_at_hook_entry': (
					None if self.debug_reading is None else
					self.debug_reading if self.debug_reading['tainted_bytes'] else
					# The byte values are kept even in the compact form: "no labels
					# here" is exactly the case where you want to see what the
					# buffer actually held.
					{'kind': 'source@entry', 'base': self.debug_reading['base'],
					 'tainted_bytes': {}, 'meta': self.debug_reading['meta'],
					 'value': self.debug_reading.get('value'),
					 'value_unreadable_offsets':
						 self.debug_reading.get('value_unreadable_offsets')}
				),
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
				if self.target['confirm'] == 'hook':
					# The mem*() veto cannot be the cause here: this hook sits on
					# KASAN's failure path and the instrumented code acts on nothing
					# it returns, so the store was never vetoed and should have
					# landed.  That makes this a defect in the target description
					# rather than an expected outcome, so say so instead of
					# offering the mem*() explanation.
					print(f'[analysis1]   NOT the expected outcome for a '
						  f'confirm=\'hook\' target: nothing acts on what '
						  f'{self.target["hook"]} returns, so no check vetoed this '
						  f'store and it should have landed.  Check, in order: '
						  f'(a) store_fn={self.target["store_fn"]} returned before '
						  f'the store — wrong store_fn, or the flagged path bails '
						  f'out after the report instead of jumping back to it; '
						  f'(b) the store landed somewhere other than the reported '
						  f'0x{self.dst:x}+{self.req_size}; (c) the watcher was '
						  f'never armed, i.e. no on_ret({self.target["hook"]}) '
						  f'arrived — look for the "dest probe live" line above.')
				else:
					print('[analysis1]   Expected when the caller ACTS on the '
						  'check\'s return value.  KASAN\'s mem*() wrappers do: '
						  '`if (!kasan_check_range(...)) return NULL;`, and '
						  'kasan_check_range() returns `!kasan_report(...)` — so a '
						  'check whose report was PRINTED vetoes the copy and there '
						  'is no store to observe.  Not a taint negative.  See '
						  '"GETTING THE STORE TO EXECUTE" at the top of this file: '
						  'either patch the wrappers and re-record, or rely on a '
						  'source-reading target (here: p9_read_work_src) which '
						  'needs no store at all.')
			elif outcome == 'store_not_read':
				print(f'[analysis1] *** INCONCLUSIVE ({tag}): a store landed at '
					  f'pc={result["last_store_pc"]} but the probe never read the '
					  f'shadow [{result["reason"]}] ***')
			elif outcome == 'unreadable':
				print(f'[analysis1] *** INCONCLUSIVE ({tag}): all '
					  f'{read["meta"]["read"]} {read["kind"]} bytes at '
					  f'{read["base"]} were untranslatable — no labels could be '
					  f'read, so this is NOT a taint negative ***')
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
			# problem, and there are far more of them than writes.  `write` is a C
			# bool, i.e. the low byte of rdx — the rest of the register is whatever
			# the caller left there, so mask before testing it or a read can look
			# like a write.
			if not (panda.arch.get_arg(cpu, 2) & 0xff):
				return None, None, None
			return panda.arch.get_arg(cpu, 0), panda.arch.get_arg(cpu, 1), None
		if kind == 'ptr':
			# __asan_report_store4_noabort(addr): the width is in the symbol name,
			# so it comes from the catalogue rather than from a register.
			return panda.arch.get_arg(cpu, 0), target['access_size'], None
		if kind == 'memcpy':
			# __asan_memcpy(to, from, size)
			return (panda.arch.get_arg(cpu, 0), panda.arch.get_arg(cpu, 2),
					panda.arch.get_arg(cpu, 1))
		raise ValueError(f'unknown args convention {kind!r}')

	def _hook_report_ip(cpu, target, stack):
		"""The `ip` a real kasan_report would have been handed, for a
		confirm='hook' target that has to synthesise its own report record.

		kasan_report takes it as arg3 (`unsigned long ret_ip`, rcx), so read it
		from the register when kasan_report is itself the hook.  The __asan_report_*
		thunks do not take it at all — they compute _RET_IP_, which is their own
		return address, i.e. callers[0]."""
		if target['args'] == 'ptr_size_write':
			return panda.arch.get_arg(cpu, 3)
		return stack[0] if stack else 0

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

			# A hook that only exists on KASAN's failure path needs no second
			# event: reaching it IS the report.  Synthesise the record from the
			# hook's own arguments so the JSON carries the same four fields a real
			# kasan_report would have given, and the same comparison against the
			# report text is possible either way.
			if target['confirm'] == 'hook':
				w.note_report(cpu, {
					'addr':     dst,
					'size':     size,
					# Every confirm='hook' entry is a store thunk; a load thunk
					# would be an out-of-bounds READ, which is not what this
					# module is for.
					'is_write': True,
					'ip':       _hook_report_ip(cpu, target, stack),
					'via':      'hook',
				})
			return

	def _on_kasan_report(cpu):
		"""KASAN only calls kasan_report() when a range check has failed, so this
		is the "the access is out of bounds" signal.

		Note it fires whether or not the report is actually PRINTED: suppression
		(one-shot, or current->kasan_depth) happens inside kasan_report, after the
		call.  That is deliberate — it is what lets a suppressed occurrence, whose
		check therefore "passes" and whose copy therefore executes, still be
		recognised as out of bounds.

		It confirms every open window in the same task whose captured access the
		report actually names; a hook nested inside another hook (memcpy ->
		kasan_check_range) can legitimately have two windows open for one access.
		A window whose target sets confirm='hook' was already confirmed at hook
		entry and is skipped here by note_report's own guard.

		NB this only runs when kasan_report is reached by a CALL.  A caller that
		tail-jumps into it — __asan_report_store*_noabort does — produces no
		on_call at all, which is why targets on that path confirm themselves; see
		"THE THIRD SHAPE" in the module docstring.
		"""
		ctr['kasan_report'] += 1

		# bool kasan_report(unsigned long addr, size_t size, bool is_write,
		#                   unsigned long ip)
		# x86_64 SysV: rdi, rsi, rdx, rcx.  is_write is a C bool, i.e. the low
		# byte of rdx.
		report = {
			'addr':     panda.arch.get_arg(cpu, 0),
			'size':     panda.arch.get_arg(cpu, 1),
			'is_write': bool(panda.arch.get_arg(cpu, 2) & 0xff),
			'ip':       panda.arch.get_arg(cpu, 3),
		}
		print(f'[analysis1] kasan_report: '
			  f'{"write" if report["is_write"] else "read"} of size '
			  f'{report["size"]} at 0x{report["addr"]:x} (ip=0x{report["ip"]:x})')

		# The frames, printed whether or not a window is open — this is how the
		# NEXT catalogue entry gets written.  A KASAN report hands you
		# `symbol+offset` and a pedigree needs a frame INDEX for it; the only way to
		# know which index, or whether the frame is on the stack at all once tail
		# calls are in play, is to see the stack the analysis itself sees.  Free,
		# because kasan_report only runs when a range check has already failed.
		stack = callers(cpu)
		print(f'[analysis1]   kasan_report callers ({len(stack)} frame(s), '
			  f'innermost first): '
			  + ' '.join(f'[{i}]=0x{a:x}' for i, a in enumerate(stack[:8]))
			  + (' ...' if len(stack) > 8 else ''))

		if not state['windows']:
			return

		# process_name() is one OSI walk; kasan_report is rare, and every open
		# window is compared against the same answer.
		pname = process_name(panda, cpu)
		for w in list(state['windows']):
			if w.closed:
				continue
			if w.cpu_index != cpu.cpu_index or pname != w.armed_by:
				print(f'[analysis1]   in task {pname!r}, not the {w.armed_by!r} '
					  f'that opened window #{w.hit} ({w.target["id"]}) — '
					  f'not confirming')
				continue
			ok, why = w.report_matches(report)
			if not ok:
				print(f'[analysis1]   not about window #{w.hit} '
					  f'({w.target["id"]}): {why} — not confirming')
				continue
			w.note_report(cpu, report)

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
			# Best-effort: find the backtrace of the mmap/brk call that created the
			# VMA containing this page.  Any key inside the VMA range qualifies —
			# covers mmap (key == VMA base) and brk (key == new-brk somewhere inside
			# the heap VMA).  Computed once per page, not per byte.
			vma_base = containing_vma['base']
			vma_end  = vma_base + containing_vma['size']
			alloc_backtrace = next(
				(bt for addr, bt in vma_backtraces.items()
				 if vma_base <= addr < vma_end),
				[],
			)
			# One page-table walk for the whole page instead of 4096.
			page_paddrs = v2p_range(cpu, page_base, PAGE_SIZE)
			for offset in range(PAGE_SIZE):
				taint_paddr = page_paddrs[offset]
				if taint_paddr is None:
					untranslatable += 1
					continue
				label_map[ctr['labels']] = {
					'virt_addr':       hex(page_base + offset),
					'backtrace':       [],
					'alloc_backtrace': alloc_backtrace,
					'type':            'zero_page',
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
			'callback_id': store_id,
			'virt_addr':   hex(ptr),
			'len':         length,
			'backtrace':   backtrace,
			'type':        'kdo_store',
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
		#
		#    Deliberately does not return: a catalogue entry may hook kasan_report
		#    ITSELF (see "THE THIRD SHAPE"), and that same call still has to
		#    confirm every other open window.  Returning here would silently
		#    disable the confirmation path for the whole replay the moment such an
		#    entry is enabled.  Nothing past #2 can apply to a hook address, so the
		#    two returns below cover both orders.
		tlist = hook_targets.get(addr)
		if tlist is not None:
			_on_hook_call(cpu, addr, tlist)

		# 2. The out-of-bounds signal.  No task filter here — the window itself
		#    checks that the report fired in the task that opened it.
		if addr == kasan_report_addr:
			_on_kasan_report(cpu)
			return
		if tlist is not None:
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
		# Record the backtrace keyed by the returned VMA base so that
		# _drain_zero_pages can attach the allocation site to zero-page labels.
		if ret < (1 << 63):  # MAP_FAILED is ~0 — don't record error returns
			vma_backtraces[ret] = [hex(a) for a in callers(cpu)]
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
		# Record the backtrace keyed by the new-brk pointer.  At drain time we
		# scan for any key within the heap VMA range, so the exact key value
		# doesn't have to equal the VMA base.
		if ret != 0:
			vma_backtraces[ret] = [hex(a) for a in callers(cpu)]
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
