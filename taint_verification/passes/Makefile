# Makefile for kdo-store-pass
#
# Mirrors what `task build` does under kernel-tools:
#   1. Run cmake pointing at the local LLVM build.
#   2. Run make inside the build directory.
#
# Usage:
#   make                                    – configure (if needed) and build
#   make clean                              – remove the build directory entirely
#   LLVM_PATH=/path/to/llvm/build make      – use a specific LLVM build

# Path to the LLVM build directory.
# Precedence (highest first):
#   1. LLVM_PATH env var / make variable  (e.g. LLVM_PATH=/home/aso/kno/llvm-project/build make)
#   2. Default: <workspace-root>/llvm-project/build  (mirrors kernel-tools/.env.default)
LLVM_PATH ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)/llvm-project/build

# cmake executable to use – can be overridden
CMAKE ?= cmake

# Number of parallel jobs
NPROC ?= $(shell nproc)

BUILD_DIR := $(dir $(lastword $(MAKEFILE_LIST)))build

.PHONY: all clean

all: $(BUILD_DIR)/Makefile
	$(MAKE) -C $(BUILD_DIR) -j$(NPROC)

# Configure step: run cmake once; re-run if the top-level CMakeLists.txt changes.
# CC/CXX must be set as environment variables before cmake's first project()
# call — passing them as -D flags is too late and cmake ignores them.
$(BUILD_DIR)/Makefile: $(dir $(lastword $(MAKEFILE_LIST)))CMakeLists.txt
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && \
	    CC=$(LLVM_PATH)/bin/clang \
	    CXX=$(LLVM_PATH)/bin/clang++ \
	    $(CMAKE) -DLLVM_DIR=$(LLVM_PATH)/lib/cmake/llvm ..

clean:
	rm -rf $(BUILD_DIR)
