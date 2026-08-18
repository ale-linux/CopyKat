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
import struct
import faulthandler
import tempfile

pattern = re.compile(r"\brepro$")

analysis = dict()
cur_syscall = dict()
memcpy_hit_ctr = 0
kasan_check_write_hit_ctr = 0
kdo_label_nr = 1

# Per-source taint call counters, for end-of-run summary
taint_source_ctr = {
	'_copy_from_user': 0,
	'_copy_from_iter': 0,
	'__get_user_1':    0,
	'__get_user_2':    0,
	'__get_user_4':    0,
	'__get_user_8':    0,
}

# ITER_UBUF / ITER_IOVEC discriminant values (enum iter_type, fixed kernel ABI)
ITER_UBUF  = 0
ITER_IOVEC = 1


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

	# iov_iter struct offsets — extracted from the debug image via GDB in rrr/__init__.py
	II_TYPE    = ki['iov_iter.iter_type_offset']
	II_DATASRC = ki['iov_iter.data_source_offset']
	II_IOVOFF  = ki['iov_iter.iov_offset_offset']
	II_BASE    = ki['iov_iter.iov_base_offset']     # __iov ptr (IOVEC) or ubuf ptr (UBUF)
	II_COUNT   = ki['iov_iter.count_offset']
	II_NRSEGS  = ki['iov_iter.nr_segs_offset']
	IOVEC_BASE = ki['iov_iter.iovec.iov_base_offset']
	IOVEC_LEN  = ki['iov_iter.iovec.iov_len_offset']

	print(
		f'[analysis1] iov_iter offsets: '
		f'iter_type={II_TYPE} data_source={II_DATASRC} iov_offset={II_IOVOFF} '
		f'iov_base={II_BASE} count={II_COUNT} nr_segs={II_NRSEGS} '
		f'iovec.base={IOVEC_BASE} iovec.len={IOVEC_LEN}'
	)

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

	# Maps label ID (int) -> {'src_virt': hex str, 'dst_virt': hex str, 'origin': str,
	#                          'backtrace': [hex str, ...]}
	label_map = {}

	# Pending copy operations: saved at on_call entry, consumed at on_ret.
	# Key: RSP value at call entry (= address of the return-address slot on the stack).
	# Value: dict with keys 'to', 'from_base', 'n', 'origin'
	pending_copies = {}

	# ----------------------------------------------------------------
	# Symbol resolution
	# ----------------------------------------------------------------
	copy_from_user_sym      = symbol_map.get('_copy_from_user', None)
	copy_from_iter_sym      = symbol_map.get('_copy_from_iter', None)
	get_user_1_sym          = symbol_map.get('__get_user_1', None)
	get_user_2_sym          = symbol_map.get('__get_user_2', None)
	get_user_4_sym          = symbol_map.get('__get_user_4', None)
	get_user_8_sym          = symbol_map.get('__get_user_8', None)
	asan_memcpy_sym         = symbol_map.get('__asan_memcpy', None)
	kasan_check_write_sym   = symbol_map.get('__kasan_check_write', None)
	copy_to_urb_sym         = (symbol_map.get('copy_to_urb.constprop.0', None)
	                            or symbol_map.get('copy_to_urb', None))
	bitmap_ip_add_sym       = symbol_map.get('bitmap_ip_add', None)
	panic_sym               = symbol_map.get('panic', None)

	copy_from_user_addr     = copy_from_user_sym.address    if copy_from_user_sym    else None
	copy_from_iter_addr     = copy_from_iter_sym.address    if copy_from_iter_sym    else None
	get_user_1_addr         = get_user_1_sym.address        if get_user_1_sym        else None
	get_user_2_addr         = get_user_2_sym.address        if get_user_2_sym        else None
	get_user_4_addr         = get_user_4_sym.address        if get_user_4_sym        else None
	get_user_8_addr         = get_user_8_sym.address        if get_user_8_sym        else None
	asan_memcpy_addr        = asan_memcpy_sym.address       if asan_memcpy_sym       else None
	kasan_check_write_addr  = kasan_check_write_sym.address if kasan_check_write_sym else None
	copy_to_urb_addr        = copy_to_urb_sym.address       if copy_to_urb_sym       else None
	bitmap_ip_add_addr      = bitmap_ip_add_sym.address     if bitmap_ip_add_sym     else None
	panic_addr              = panic_sym.address             if panic_sym             else None

	# The offending call is at copy_to_urb+0x308; the return address pushed on
	# the stack (what callstack_instr exposes as the immediate caller) is the
	# next instruction: copy_to_urb+0x309.
	copy_to_urb_memcpy_retaddr    = copy_to_urb_addr   + 0x309 if copy_to_urb_addr   is not None else None
	bitmap_ip_add_kasan_retaddr   = bitmap_ip_add_addr  + 0x3c0 if bitmap_ip_add_addr is not None else None

	# Addresses we need an on_ret for (copy functions only — __get_user_N label on call)
	copy_ret_addrs = {a for a in (copy_from_user_addr, copy_from_iter_addr) if a is not None}

	print(f'[analysis1] _copy_from_user addr:      {hex(copy_from_user_addr) if copy_from_user_addr else "NOT FOUND"}')
	print(f'[analysis1] _copy_from_iter addr:      {hex(copy_from_iter_addr) if copy_from_iter_addr else "NOT FOUND"}')
	print(f'[analysis1] __get_user_1 addr:         {hex(get_user_1_addr) if get_user_1_addr else "NOT FOUND"}')
	print(f'[analysis1] __get_user_2 addr:         {hex(get_user_2_addr) if get_user_2_addr else "NOT FOUND"}')
	print(f'[analysis1] __get_user_4 addr:         {hex(get_user_4_addr) if get_user_4_addr else "NOT FOUND"}')
	print(f'[analysis1] __get_user_8 addr:         {hex(get_user_8_addr) if get_user_8_addr else "NOT FOUND"}')
	print(f'[analysis1] __asan_memcpy addr:        {hex(asan_memcpy_addr) if asan_memcpy_addr else "NOT FOUND"}')
	print(f'[analysis1] __kasan_check_write addr:  {hex(kasan_check_write_addr) if kasan_check_write_addr else "NOT FOUND"}')
	print(f'[analysis1] copy_to_urb addr:          {hex(copy_to_urb_addr) if copy_to_urb_addr else "NOT FOUND"}')
	print(f'[analysis1] copy_to_urb retaddr:       {hex(copy_to_urb_memcpy_retaddr) if copy_to_urb_memcpy_retaddr else "NOT FOUND"}')
	print(f'[analysis1] bitmap_ip_add addr:        {hex(bitmap_ip_add_addr) if bitmap_ip_add_addr else "NOT FOUND"}')
	print(f'[analysis1] bitmap_ip_add retaddr:     {hex(bitmap_ip_add_kasan_retaddr) if bitmap_ip_add_kasan_retaddr else "NOT FOUND"}')
	print(f'[analysis1] panic addr:                {hex(panic_addr) if panic_addr else "NOT FOUND"}')

	# ----------------------------------------------------------------
	# Helpers
	# ----------------------------------------------------------------

	def log(s):
		if enable_logging:
			print(s, file=outfile)

	def vmread64(cpu, addr):
		try:
			raw = panda.virtual_memory_read(cpu, addr, 8)
			return struct.unpack_from('<Q', raw)[0]
		except Exception:
			return None

	def vmread8(cpu, addr):
		try:
			raw = panda.virtual_memory_read(cpu, addr, 1)
			return raw[0]
		except Exception:
			return None

	def enable_taint():
		if not panda.taint_enabled():
			panda.taint_enable()

	def get_taint_labels(cpu, addr):
		"""Return the set of taint labels on the byte at virtual address `addr`."""
		taint_paddr = panda.virt_to_phys(cpu, addr)
		result = panda.taint_get_ram(taint_paddr)
		if result is None:
			return None
		return result.get_labels()

	def _delete_taint_range(cpu, virt, length):
		"""
		Delete any existing taint on `length` bytes starting at virtual address
		`virt`.  Must be called before re-labelling a buffer so that stale labels
		from a previous copy into the same memory do not merge with the new ones.
		"""
		deleted = 0
		for offset in range(length):
			paddr = panda.virt_to_phys(cpu, virt + offset)
			if paddr == 0xffffffffffffffff:
				continue
			result = panda.taint_get_ram(paddr)
			if result is not None and result.get_labels():
				panda.plugins['taint2'].taint2_delete_ram(paddr)
				deleted += 1
		if deleted:
			log(f'taint: deleted stale taint on {deleted}/{length} bytes at 0x{virt:x}')
			print(f'[analysis1]   deleted stale taint on {deleted}/{length} bytes at 0x{virt:x}')

	def _do_taint_range(cpu, dst_virt, length, origin, from_base, backtrace, user_context=None):
		"""
		Label `length` bytes at kernel virtual address `dst_virt`.
		Called from on_ret after the copy has completed, so labels stick.
		Stale taint is deleted first so re-used buffers don't accumulate labels.
		Each byte gets a fresh label recording the corresponding userspace
		source VA (from_base + offset) for traceability.
		"""
		global kdo_label_nr
		_delete_taint_range(cpu, dst_virt, length)
		labeled = 0
		for offset in range(length):
			dst = dst_virt + offset
			paddr = panda.virt_to_phys(cpu, dst)
			if paddr == 0xffffffffffffffff:
				print(f'[analysis1]   virt_to_phys failed for dst 0x{dst:x}, skipping byte {offset}/{length}')
				log(f'taint: virt_to_phys failed for dst 0x{dst:x}, skipping')
				continue
			src = from_base + offset if from_base is not None else None
			panda.taint_label_ram(paddr, kdo_label_nr)
			label_map[kdo_label_nr] = {
				'dst_virt':     hex(dst),
				'src_virt':     hex(src) if src is not None else None,
				'origin':       origin,
				'backtrace':    backtrace,
				'user_context': user_context,
			}
			log(f'taint: label {kdo_label_nr} -> dst 0x{dst:x} (phys 0x{paddr:x})'
			    + (f' src 0x{src:x}' if src is not None else '')
			    + f' [{origin}]')
			kdo_label_nr += 1
			labeled += 1
		if labeled:
			print(f'[analysis1]   tainted {labeled}/{length} bytes dst=0x{dst_virt:x} [{origin}], '
			      f'labels {kdo_label_nr - labeled}..{kdo_label_nr - 1}')
		else:
			print(f'[analysis1]   WARNING: 0 bytes tainted for dst=0x{dst_virt:x} n={length} [{origin}]')

	def _do_taint_user_src(cpu, user_virt, length, origin, backtrace, user_context=None):
		"""
		Label `length` bytes at userspace virtual address `user_virt`.
		Used for __get_user_N: we place the label on the source *before* the
		load inside the stub so that taint2 propagates it automatically through
		`mov (%rax), %rdx` and into wherever the caller stores the result.
		Stale taint is deleted first to avoid label accumulation on re-read pages.
		"""
		global kdo_label_nr
		_delete_taint_range(cpu, user_virt, length)
		labeled = 0
		for offset in range(length):
			virt = user_virt + offset
			paddr = panda.virt_to_phys(cpu, virt)
			if paddr == 0xffffffffffffffff:
				print(f'[analysis1]   virt_to_phys failed for user src 0x{virt:x}, skipping byte {offset}/{length}')
				log(f'taint: virt_to_phys failed for user src 0x{virt:x}, skipping')
				continue
			panda.taint_label_ram(paddr, kdo_label_nr)
			label_map[kdo_label_nr] = {
				'dst_virt':     None,   # unknown — propagated by taint2 into caller's store
				'src_virt':     hex(virt),
				'origin':       origin,
				'backtrace':    backtrace,
				'user_context': user_context,
			}
			log(f'taint: label {kdo_label_nr} -> user src 0x{virt:x} (phys 0x{paddr:x}) [{origin}]')
			kdo_label_nr += 1
			labeled += 1
		if labeled:
			print(f'[analysis1]   tainted {labeled}/{length} user-src bytes 0x{user_virt:x} [{origin}], '
			      f'labels {kdo_label_nr - labeled}..{kdo_label_nr - 1}')
		else:
			print(f'[analysis1]   WARNING: 0 user-src bytes tainted for 0x{user_virt:x} n={length} [{origin}]')

	# Build get_user dispatch table once, outside on_call
	get_user_map = {}
	if get_user_1_addr is not None: get_user_map[get_user_1_addr] = ('__get_user_1', 1)
	if get_user_2_addr is not None: get_user_map[get_user_2_addr] = ('__get_user_2', 2)
	if get_user_4_addr is not None: get_user_map[get_user_4_addr] = ('__get_user_4', 4)
	if get_user_8_addr is not None: get_user_map[get_user_8_addr] = ('__get_user_8', 8)

	# ----------------------------------------------------------------
	# all_sysenter: snapshot userspace backtrace + syscall args on every
	#               syscall issued by the reproducer process.
	# ----------------------------------------------------------------
	def all_sysenter(cpu, pc, callno):
		global cur_syscall
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			return
		cur_syscall.clear()
		cur_syscall['n']        = callno
		cur_syscall['backtrace'] = [hex(a) for a in panda.callstack_callers(20, cpu)]
		cur_syscall['rdi'] = panda.arch.get_reg(cpu, "RDI")
		cur_syscall['rsi'] = panda.arch.get_reg(cpu, "RSI")
		cur_syscall['rdx'] = panda.arch.get_reg(cpu, "RDX")
		cur_syscall['r10'] = panda.arch.get_reg(cpu, "R10")
		cur_syscall['r8']  = panda.arch.get_reg(cpu, "R8")
		cur_syscall['r9']  = panda.arch.get_reg(cpu, "R9")

	# ----------------------------------------------------------------
	# on_call: save args for copy functions; taint src for __get_user_N;
	#          read taint at sink sites (__asan_memcpy / __kasan_check_write)
	# ----------------------------------------------------------------
	def on_call(cpu, addr):
		global memcpy_hit_ctr, kasan_check_write_hit_ctr, analysis, taint_source_ctr

		# Only care about calls from the reproducer process
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			return

		# -------- taint sources ----------------------------------------

		# _copy_from_user(void *to, const void __user *from, unsigned long n)
		#   rdi=to  rsi=from  rdx=n
		# Save args now; label dst in on_ret when the copy is complete.
		if copy_from_user_addr is not None and addr == copy_from_user_addr:
			to    = panda.arch.get_arg(cpu, 0)
			from_ = panda.arch.get_arg(cpu, 1)
			n     = panda.arch.get_arg(cpu, 2)
			if n == 0 or n > 0x100000:
				return
			enable_taint()
			rsp = panda.arch.get_reg(cpu, "RSP")
			pending_copies[rsp] = {
				'func_addr':   addr,
				'to':          to,
				'from_base':   from_,
				'n':           n,
				'origin':      '_copy_from_user',
				'backtrace':   [hex(a) for a in panda.callstack_callers(20, cpu)],
				'user_context': cur_syscall.copy(),
			}
			taint_source_ctr['_copy_from_user'] += 1
			print(f'[analysis1] _copy_from_user #{taint_source_ctr["_copy_from_user"]}(to=0x{to:x}, from=0x{from_:x}, n={n}) — pending on_ret rsp=0x{rsp:x}')
			return

		# _copy_from_iter(void *addr, size_t bytes, struct iov_iter *i)
		#   rdi=addr  rsi=bytes  rdx=i
		# Only taint when data_source==1 (user→kernel) and iter_type is UBUF or IOVEC.
		# Save args now; label dst in on_ret when the copy is complete.
		if copy_from_iter_addr is not None and addr == copy_from_iter_addr:
			dst    = panda.arch.get_arg(cpu, 0)
			nbytes = panda.arch.get_arg(cpu, 1)
			iter_p = panda.arch.get_arg(cpu, 2)
			if nbytes == 0 or nbytes > 0x100000:
				return
			enable_taint()

			iter_type   = vmread8(cpu, iter_p + II_TYPE)
			data_source = vmread8(cpu, iter_p + II_DATASRC)
			print(f'[analysis1] _copy_from_iter probe: iter_type={iter_type} data_source={data_source} dst=0x{dst:x} bytes={nbytes}')
			if iter_type is None or not data_source:
				print(f'[analysis1]   _copy_from_iter: skipping (iter_type={iter_type} data_source={data_source})')
				return
			if iter_type not in (ITER_UBUF, ITER_IOVEC):
				print(f'[analysis1]   _copy_from_iter: unsupported iter_type={iter_type}, skipping')
				log(f'_copy_from_iter: unsupported iter_type={iter_type}, skipping')
				return

			# Resolve userspace source base for per-byte label annotation.
			from_base = None
			if iter_type == ITER_UBUF:
				# ubuf holds the single userspace pointer; iov_offset is consumed bytes
				ubuf       = vmread64(cpu, iter_p + II_BASE)
				iov_offset = vmread64(cpu, iter_p + II_IOVOFF) or 0
				if ubuf is not None:
					from_base = ubuf + iov_offset
			elif iter_type == ITER_IOVEC:
				# __iov points to the current struct iovec; iov_offset is bytes into it
				iov_ptr    = vmread64(cpu, iter_p + II_BASE)
				iov_offset = vmread64(cpu, iter_p + II_IOVOFF) or 0
				if iov_ptr is not None:
					iov_base = vmread64(cpu, iov_ptr + IOVEC_BASE)
					if iov_base is not None:
						from_base = iov_base + iov_offset

			rsp = panda.arch.get_reg(cpu, "RSP")
			pending_copies[rsp] = {
				'func_addr':   addr,
				'to':          dst,
				'from_base':   from_base,
				'n':           nbytes,
				'origin':      '_copy_from_iter',
				'backtrace':   [hex(a) for a in panda.callstack_callers(20, cpu)],
				'user_context': cur_syscall.copy(),
			}
			taint_source_ctr['_copy_from_iter'] += 1
			print(f'[analysis1] _copy_from_iter #{taint_source_ctr["_copy_from_iter"]}(dst=0x{dst:x}, bytes={nbytes}, '
			      f'iter_type={iter_type}' +
			      (f', src~0x{from_base:x})' if from_base else ', src=unknown)') +
			      f' — pending on_ret rsp=0x{rsp:x}')
			return

		# __get_user_1/2/4/8
		#   On entry: %rax = userspace virtual address to read from
		#
		# Label the source bytes NOW (before the load inside the stub).
		# taint2 propagates the label through `mov (%rax), %rdx` and into
		# wherever the caller stores the result — no on_ret needed.
		if addr in get_user_map:
			origin, sz = get_user_map[addr]
			user_addr = panda.arch.get_reg(cpu, "RAX")
			taint_source_ctr[origin] += 1
			print(f'[analysis1] {origin} #{taint_source_ctr[origin]}(user=0x{user_addr:x})')
			enable_taint()
			backtrace = [hex(a) for a in panda.callstack_callers(20, cpu)]
			_do_taint_user_src(cpu, user_addr, sz, origin, backtrace, cur_syscall.copy())
			return

		# -------- taint sinks (unchanged) ------------------------------

		if panic_addr is not None and addr == panic_addr:
			analysis['memcpy_hit_ctr'] = memcpy_hit_ctr
			log('PANIC!')
			print(f"[analysis1] PANIC reached — memcpy_hit_ctr={memcpy_hit_ctr}")
			panda.end_analysis()
			return

		callers = list(panda.callstack_callers(20, cpu))
		immediate_caller = callers[0] if callers else None

		# __asan_memcpy(void *to, const void *from, uptr size)  rdi=to rsi=from rdx=size
		if asan_memcpy_addr is not None and addr == asan_memcpy_addr:
			is_target = (immediate_caller == copy_to_urb_memcpy_retaddr)
			memcpy_hit_ctr += 1

			if is_target:
				print(f"[analysis1] *** TARGET HIT #{len(analysis.get('copy_to_urb_memcpy_calls', [])) + 1} at memcpy call #{memcpy_hit_ctr} ***")
				print(f"[analysis1] __asan_memcpy #{memcpy_hit_ctr} in '{pname}' caller={hex(immediate_caller) if immediate_caller else 'none'}")
				log(f'__asan_memcpy call #{memcpy_hit_ctr}:')

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
					'hit':           memcpy_hit_ctr,
					'backtrace':     [hex(a) for a in callers],
					'from':          hex(from_ptr),
					'size':          size,
					'tainted_bytes': tainted_bytes,
				})
			return

		# __kasan_check_write(const volatile void *p, unsigned int size)  rdi=p rsi=size
		if kasan_check_write_addr is not None and addr == kasan_check_write_addr:
			is_target = (immediate_caller == bitmap_ip_add_kasan_retaddr)
			kasan_check_write_hit_ctr += 1

			if is_target:
				print(f"[analysis1] *** TARGET HIT #{len(analysis.get('bitmap_ip_add_kasan_check_writes', [])) + 1} at kasan_check_write call #{kasan_check_write_hit_ctr} ***")
				print(f"[analysis1] __kasan_check_write #{kasan_check_write_hit_ctr} in '{pname}' caller={hex(immediate_caller) if immediate_caller else 'none'}")
				log(f'__kasan_check_write call #{kasan_check_write_hit_ctr}:')

				ptr  = panda.arch.get_arg(cpu, 0)
				size = panda.arch.get_arg(cpu, 1)
				tainted_bytes = {}
				for offset in range(size):
					labels = get_taint_labels(cpu, ptr + offset)
					if labels:
						resolved = [label_map[l] for l in labels if l in label_map]
						tainted_bytes[offset] = resolved
						log(f'  taint: ptr[{offset}] @ 0x{ptr + offset:x} labels={labels} resolved={resolved}')
				if tainted_bytes:
					print(f'[analysis1]   tainted write bytes: {tainted_bytes}')
				else:
					print(f'[analysis1]   no taint on write bytes (ptr=0x{ptr:x}, size={size})')

				analysis.setdefault('bitmap_ip_add_kasan_check_writes', []).append({
					'hit':           kasan_check_write_hit_ctr,
					'backtrace':     [hex(a) for a in callers],
					'from':          hex(ptr),
					'size':          size,
					'tainted_bytes': tainted_bytes,
				})
			return

	# ----------------------------------------------------------------
	# on_ret: label kernel dst after copy functions have completed
	# ----------------------------------------------------------------
	def on_ret(cpu, addr):
		if addr not in copy_ret_addrs:
			return

		# At on_call, RSP pointed at the return-address slot (pre-call stack top).
		# By the time on_ret fires, `ret` has already popped that slot, so RSP is
		# 8 bytes higher.  Subtract 8 to recover the key we stored in on_call.
		rsp = panda.arch.get_reg(cpu, "RSP")
		entry = pending_copies.pop(rsp - 8, None)
		if entry is None:
			print(f'[analysis1] on_ret: no pending entry for addr=0x{addr:x} rsp=0x{rsp:x} key=0x{rsp-8:x} (cross-process or RSP mismatch)')
			return

		# Guard: only taint for the reproducer process
		pname = panda.get_process_name(cpu)
		if not pattern.search(pname):
			print(f'[analysis1] on_ret: discarding pending {entry["origin"]} for non-repro process {pname!r}')
			return

		print(f'[analysis1] on_ret: completing {entry["origin"]} to=0x{entry["to"]:x} n={entry["n"]} '
		      + (f'from~0x{entry["from_base"]:x}' if entry["from_base"] else 'from=unknown'))
		_do_taint_range(cpu, entry['to'], entry['n'], entry['origin'],
		                entry['from_base'], entry['backtrace'], entry.get('user_context'))

	@panda.ppp("syscalls2", "on_sys_execve_enter")
	def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
		try:
			fname_bytes = panda.virtual_memory_read(cpu, fname_ptr, 256)
		except Exception:
			print("[analysis1] warning: could not read execve fname")
			return
		fname = fname_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')

		if not pattern.search(fname):
			return

		print(f"[analysis1] repro execve detected: {fname} — enabling on_call/on_ret hooks")
		panda.ppp("callstack_instr", "on_call")(on_call)
		panda.ppp("callstack_instr", "on_ret")(on_ret)
		panda.ppp("syscalls2", "on_all_sys_enter")(all_sysenter)
		panda.disable_ppp("on_sys_execve_enter")

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
	print(f'[analysis1] total __asan_memcpy calls in repro:       {memcpy_hit_ctr}')
	print(f'[analysis1] copy_to_urb target hits:                  {len(analysis.get("copy_to_urb_memcpy_calls", []))}')
	print(f'[analysis1] total __kasan_check_write calls in repro: {kasan_check_write_hit_ctr}')
	print(f'[analysis1] bitmap_ip_add target hits:                {len(analysis.get("bitmap_ip_add_kasan_check_writes", []))}')
	print(f'[analysis1] pending unmatched copies at exit:         {len(pending_copies)}')
	print(f'[analysis1] total taint labels created:               {total_labels}')
	print(f'[analysis1] taint source call counts:')
	for src, ctr in taint_source_ctr.items():
		print(f'[analysis1]   {src}: {ctr}')

	analysis['memcpy_hit_ctr']             = memcpy_hit_ctr
	analysis['kasan_check_write_hit_ctr']  = kasan_check_write_hit_ctr
	analysis['replay_time']                = end - start
	analysis['total_taint_labels']         = total_labels
	analysis['pending_copies_at_exit']     = len(pending_copies)
	analysis['taint_source_ctrs']          = taint_source_ctr
	with open('./analysis1.json', 'w') as f:
		f.write(json.dumps(analysis, indent=2))


def replay(rootfs, kernel, enable_logging=True, record='record'):
	print("starting")
	rrr.replay(rootfs, kernel, record, __replay,
			   additional_args=[enable_logging])
