#include "hash_hook_id.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"

#include <cstring>
#include <openssl/evp.h>

using namespace llvm;

uint32_t get_basic_block_offset(BasicBlock *BB, Instruction *Inst) {
  uint32_t Offset = 0;
  for (Instruction &I : *BB) {
    Offset += 1;
    if (&I == Inst)
      return Offset;
  }
  return -1;
}

static std::string sha256(const std::string &Str) {
  EVP_MD_CTX *MdCtx;
  const EVP_MD *Md;
  unsigned char Hash[EVP_MAX_MD_SIZE];
  unsigned int HashLen;

  OpenSSL_add_all_digests();

  Md = EVP_sha256();

  if (!(MdCtx = EVP_MD_CTX_new()))
    return "";

  EVP_DigestInit_ex(MdCtx, Md, NULL);
  EVP_DigestUpdate(MdCtx, Str.c_str(), Str.size());
  EVP_DigestFinal_ex(MdCtx, Hash, &HashLen);
  EVP_MD_CTX_free(MdCtx);

  return std::string(reinterpret_cast<char *>(Hash), HashLen);
}

uint64_t truncateSHA256To64Bit(const std::string &Hash) {
  if (Hash.size() < sizeof(uint64_t))
    return 0;

  uint64_t Result = 0;
  std::memcpy(&Result, Hash.data(), sizeof(Result));
  return Result;
}

uint64_t get_hook_id(const std::string &Str) {
  return truncateSHA256To64Bit(sha256(Str));
}

std::string get_hook_id_full(const std::string &Str) {
  const std::string Raw = sha256(Str);
  static const char Hex[] = "0123456789abcdef";
  std::string Out;
  Out.reserve(Raw.size() * 2);
  for (unsigned char C : Raw) {
    Out += Hex[C >> 4];
    Out += Hex[C & 0xf];
  }
  return Out;
}

std::string buildHookHash(const Instruction &I, bool IncludeFunction) {
  std::string Result;

  std::string DbgStr = "no_dbg";
  if (const DILocation *DL = I.getDebugLoc()) {
    while (DL) {
      DbgStr += DL->getFilename().str();
      DbgStr += ":";
      DbgStr += std::to_string(DL->getLine());
      DbgStr += ":";
      DbgStr += std::to_string(DL->getColumn());

      DL = DL->getInlinedAt();
      if (DL)
        DbgStr += "|inlinedAt:";
    }
  }

  Result += DbgStr;
  Result += "|";

  if (IncludeFunction) {
    if (const Function *F = I.getFunction())
      Result += F->getName().str();
    else
      Result += "no_func";
    Result += "|";
  }

  Result += I.getOpcodeName();
  Result += "|";

  {
    std::string TypeStr;
    raw_string_ostream TS(TypeStr);
    I.getType()->print(TS);
    Result += TypeStr;
  }
  Result += "|";

  for (unsigned Idx = 0; Idx < I.getNumOperands(); ++Idx) {
    const Value *Op = I.getOperand(Idx);

    std::string OpTypeStr;
    raw_string_ostream OTS(OpTypeStr);
    Op->getType()->print(OTS);
    Result += OpTypeStr;

    if (const ConstantInt *CI = dyn_cast<ConstantInt>(Op))
      Result += ":ci=" + std::to_string(CI->getSExtValue());
    else if (const ConstantFP *CF = dyn_cast<ConstantFP>(Op)) {
      SmallString<32> FPStr;
      CF->getValueAPF().toString(FPStr);
      Result += ":cf=" + FPStr.str().str();
    } else if (isa<ConstantPointerNull>(Op))
      Result += ":null";
    else if (const GlobalValue *GV = dyn_cast<GlobalValue>(Op))
      Result += ":gv=" + GV->getName().str();

    Result += "|";
  }

  return Result;
}
