# kdo-store-pass

An LLVM module pass that instruments every **store instruction** and every call
to the **`llvm.memcpy` / `llvm.memset` / `llvm.memmove` intrinsics** by
inserting a call to

```c
void kdo_store_callback(int id, void *ptr, int len);
```

immediately *after* each detected operation.

| Argument | Value |
|----------|-------|
| `id`     | Monotonically increasing compile-time integer, unique per instrumented site |
| `ptr`    | Destination address of the store / memcpy / memset |
| `len`    | Byte size of the write — from the stored type's `DataLayout` size for stores, or the length operand (arg 2) for intrinsics |

---

## Directory layout

```
passes/
├── CMakeLists.txt          # top-level cmake project
├── Makefile                # convenience wrapper (see below)
└── kdo-store-pass/
    ├── CMakeLists.txt      # defines the shared library target
    └── KdoStorePass.cpp    # the pass itself
```

---

## Prerequisites

* The local LLVM build that lives at `<workspace-root>/llvm-project/build`
  (the same location referenced by `kernel-tools/.env.default`).
* `cmake` ≥ 3.4.3
* A C++17-capable compiler (the local clang is used automatically)

---

## Building

From this directory (`passes/`):

```sh
make
```

The shared library is written to `passes/build/kdo-store-pass/LLVMKdoStorePass.so`.

### Overriding the LLVM prefix

If your LLVM build lives somewhere else:

```sh
make LLVMPREFIX=/opt/llvm-18
```

### Cleaning

```sh
make clean
```

---

## Using the pass

Load the plugin with `opt` and run the `kdo-store` pipeline name:

```sh
opt -load-pass-plugin=build/kdo-store-pass/LLVMKdoStorePass.so \
    -passes="kdo-store" \
    -S input.ll -o instrumented.ll
```

Or inject it at clang compile time:

```sh
clang -fpass-plugin=build/kdo-store-pass/LLVMKdoStorePass.so \
      -c source.c -o source.o
```

The pass is also registered on `registerPipelineStartEPCallback`, so when
loaded via `-fpass-plugin` it will run automatically at the start of every
compilation pipeline without needing an explicit `-passes=` flag.

---

## Providing the runtime

The pass only *declares* `kdo_store_callback` as an external symbol.  You must
link an object that defines it, e.g.:

```c
// kdo_runtime.c
#include <stdio.h>
void kdo_store_callback(int id, void *ptr, int len) {
    printf("store id=%d ptr=%p len=%d\n", id, ptr, len);
}
```
