# Building External Libraries with `KdoStorePass`

This guide outlines how to build third-party C/C++ libraries (such as `libmnl-1.0.5` and `libnftnl-1.2.5`) instrumented with the `KdoStorePass` LLVM compiler plugin.

---

## 1. Build the LLVM Pass Plugin

Ensure the pass shared library (`LLVMKdoStorePass.so`) is compiled:

```bash
cd /home/aso/workdir/CopyKat/taint_verification/passes
env LLVM_PATH=/home/aso/kno/llvm-project/build make
```

Plugin output path:
```
/home/aso/workdir/CopyKat/taint_verification/passes/build/kdo-store-pass/LLVMKdoStorePass.so
```

---

## 2. General Rules & Gotchas for Autotools / `configure`

1. **Do NOT export `CFLAGS` with `-fpass-plugin` during `./configure`**:
   - `configure` compiles small test programs (e.g. `conftest.c`) and tries to link them as standalone executables.
   - If `-fpass-plugin` is active during `configure`, `kdo_store_callback` will be injected into `conftest.c`, causing `configure` to fail with `undefined reference to kdo_store_callback` / `C compiler cannot create executables`.
   - **Solution**: Run `./configure` with `CFLAGS` unset (or standard flags), and pass the plugin flags at the `make` step using the per-target variable (see below).

2. **Use per-target `*_CFLAGS`, not `CFLAGS`, at the `make` step**:
   - Passing plugin flags via `CFLAGS=...` to `make` causes libtool to forward them to the link step, where `ld` receives `-load` and fails with `cannot find -load`.
   - The fix is to use the automake per-target variable (e.g. `libmnl_la_CFLAGS`). Libtool only applies these flags to compilation units for that target and never forwards them to the linker.
   - You also need both `-Xclang -load -Xclang <plugin>` **and** `-fpass-plugin=<plugin>`: the former registers the pass option (`cl::opt`) with LLVM's option parser; the latter loads the plugin via the new pass manager so `-mllvm` arguments are recognised.

3. **Pass Plugin Syntax**:
   ```bash
   libmnl_la_CFLAGS="-O0 -Xclang -load -Xclang /path/to/LLVMKdoStorePass.so -fpass-plugin=/path/to/LLVMKdoStorePass.so -mllvm -kdo-store-db=/path/to/IDs.db"
   ```

4. **Verifying Instrumentation**:
   - For `.so` (shared libraries):
     ```bash
     objdump -dglS path/to/library.so | grep "call.*kdo"
     ```
   - For `.a` (static archives):
     External calls in unlinked `.a` files appear as relocation entries rather than resolved PLT targets:
     ```bash
     objdump -dr path/to/library.a | grep kdo
     # or
     nm path/to/library.a | grep kdo_store_callback
     ```

---

## 3. Step-by-Step Build Walkthrough

### Set Common Paths

```bash
export WORKSPACE="/home/aso/workdir"
export PASS_PLUGIN="${WORKSPACE}/CopyKat/taint_verification/passes/build/kdo-store-pass/LLVMKdoStorePass.so"
export CLANG_BIN="/home/aso/kno/llvm-project/build/bin/clang"
export CC="${CLANG_BIN}"
export KDO_DB="/path/to/IDs.db"   # path to your sorted SHA-256 IDs database
```

---

### Step A: Build and Install `libmnl-1.0.5`

```bash
cd "${WORKSPACE}/libmnl-1.0.5"

# 1. Configure WITHOUT pass plugin in CFLAGS
unset CFLAGS
./configure --prefix="${WORKSPACE}/install" --enable-static --enable-shared

# 2. Build injecting the pass plugin via make
#    Use the per-target variable to prevent libtool from forwarding
#    plugin flags to the linker.
make clean
make V=1 libmnl_la_CFLAGS="-O0 -Xclang -load -Xclang ${PASS_PLUGIN} -fpass-plugin=${PASS_PLUGIN} -mllvm -kdo-store-db=${KDO_DB}" -j$(nproc)
make install
```

---

### Step B: Build and Install `libnftnl-1.2.5`

`libnftnl` depends on `libmnl`. Point `PKG_CONFIG_PATH` to the `install` folder from Step A.

```bash
cd "${WORKSPACE}/libnftnl-1.2.5"

# 1. Export pkgconfig path to locate libmnl
export PKG_CONFIG_PATH="${WORKSPACE}/install/lib/pkgconfig:${PKG_CONFIG_PATH}"

# 2. Configure WITHOUT pass plugin in CFLAGS
unset CFLAGS
./configure --prefix="${WORKSPACE}/install" --enable-static --enable-shared

# 3. Build injecting the pass plugin via make
#    Use the per-target variable to prevent libtool from forwarding
#    plugin flags to the linker.
make clean
make V=1 libnftnl_la_CFLAGS="-O0 -Xclang -load -Xclang ${PASS_PLUGIN} -fpass-plugin=${PASS_PLUGIN} -mllvm -kdo-store-db=${KDO_DB}" -j$(nproc)
make install
```

---

## 4. Callback Stub in the Main Binary / Repro

When linking your final executable or repro against the instrumented `.so` or `.a`, provide the definition for `kdo_store_callback`.

To prevent the compiler from optimizing away, inlining, or stripping the callback:

```c
#include <stdint.h>

/*
 * Attributes:
 * - noinline:              prevents inlining
 * - used:                  prevents dead-code elimination / stripping
 * - visibility("default"): ensures visibility for dynamic linking
 * - optnone:               disables LLVM optimization passes on this function
 */
__attribute__((noinline, used, visibility("default"), optnone))
void kdo_store_callback(int id, void *ptr, int len) {
    __asm__ __volatile__("" :: "r"(id), "r"(ptr), "r"(len) : "memory");
}
```

### Linking notes:
- **Static linking (`-static` / `.a`)**: Link order matters. Put the source/object file providing `kdo_store_callback` **before** the static libraries:
  ```bash
  clang -static repro.c -L${WORKSPACE}/install/lib -lnftnl -lmnl -o repro
  ```
- **Dynamic linking (`.so`)**: Pass `-rdynamic` (or `-Wl,--export-dynamic`) when building the executable so `ld.so` exposes `kdo_store_callback` to the shared libraries:
  ```bash
  clang -rdynamic repro.c -L${WORKSPACE}/install/lib -lnftnl -lmnl -o repro
  ```
