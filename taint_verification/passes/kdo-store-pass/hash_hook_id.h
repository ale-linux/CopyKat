#ifndef __KDO_HASH_MODULE_H
#define __KDO_HASH_MODULE_H

#include "llvm/IR/Instructions.h"

#include <cstdint>
#include <string>

uint32_t get_basic_block_offset(llvm::BasicBlock *BB, llvm::Instruction *Inst);
uint64_t truncateSHA256To64Bit(const std::string &Hash);
uint64_t get_hook_id(const std::string &Str);
// Returns the full SHA-256 of Str as a 64-character lowercase hex string.
// Use this instead of get_hook_id() when collisions must be impossible.
std::string get_hook_id_full(const std::string &Str);
std::string buildHookHash(const llvm::Instruction &I,
                          bool IncludeFunction = true);

#endif
