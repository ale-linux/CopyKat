// KdoStorePass.cpp
//
// LLVM instrumentation pass that inserts a call to
//
//   void kdo_store_callback(int id, void *ptr, int len)
//
// immediately *after* every store instruction and after every call to the
// llvm.memcpy / llvm.memset memory intrinsics.
//
// Arguments injected at each site:
//   id  – monotonically increasing integer, unique per-site (assigned at
//          compile time in the order the pass visits them)
//   ptr – destination address of the store / memcpy / memset
//   len – byte width of the write
//         • StoreInst  : derived from the stored value's type via DataLayout
//         • memcpy/memset intrinsic : the length operand (arg index 2)

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"    // MemCpyInst, MemSetInst
#include "llvm/IR/Intrinsics.h"       // Intrinsic::memcpy, Intrinsic::memset
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// ---------------------------------------------------------------------------
// getOrInsertCallback – lazily declare kdo_store_callback in the module.
//
//   void kdo_store_callback(int id, void *ptr, int len)
//
// We use i32 for id and len, and ptr is represented as i8* (opaque ptr in
// LLVM 15+, which is just 'ptr').
// ---------------------------------------------------------------------------
static FunctionCallee getOrInsertCallback(Module &M) {
  LLVMContext &Ctx = M.getContext();
  Type *VoidTy  = Type::getVoidTy(Ctx);
  Type *Int32Ty = Type::getInt32Ty(Ctx);
  Type *PtrTy   = PointerType::getUnqual(Ctx); // opaque pointer (ptr)

  FunctionType *FT = FunctionType::get(VoidTy,
                                       {Int32Ty, PtrTy, Int32Ty},
                                       /*isVarArg=*/false);
  return M.getOrInsertFunction("kdo_store_callback", FT);
}

// ---------------------------------------------------------------------------
// KdoStorePass – function pass that walks every instruction and instruments
// stores and memory intrinsics.
// ---------------------------------------------------------------------------
namespace {

struct KdoStorePass : PassInfoMixin<KdoStorePass> {

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const DataLayout &DL = M.getDataLayout();
    LLVMContext &Ctx     = M.getContext();
    FunctionCallee CB    = getOrInsertCallback(M);

    Type *Int32Ty = Type::getInt32Ty(Ctx);
    Type *PtrTy   = PointerType::getUnqual(Ctx);

    // Running counter: gives each instrumentation site a unique id.
    int SiteID = 0;

    // We collect instrumentation points first, then apply them, so we never
    // invalidate the iterator while walking the instruction list.
    struct Site {
      Instruction *InsertAfter; // insert the callback call after this inst
      Value       *Ptr;         // destination pointer
      Value       *Len;         // byte length (as i64 or i32 — will be trunc'd)
    };

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      // Never instrument the callback itself — that would cause infinite recursion.
      if (F.getName() == "kdo_store_callback")
        continue;

      SmallVector<Site, 16> Sites;

      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {

          // ── StoreInst ─────────────────────────────────────────────────────
          if (auto *SI = dyn_cast<StoreInst>(&I)) {
            Type  *StoredTy = SI->getValueOperand()->getType();
            // Ask the DataLayout for the exact store size in bytes.
            TypeSize TS     = DL.getTypeStoreSize(StoredTy);
            Value   *LenVal = ConstantInt::get(Int32Ty,
                                               static_cast<uint32_t>(TS.getFixedValue()));
            Sites.push_back({SI, SI->getPointerOperand(), LenVal});
            continue;
          }

          // ── memcpy / memset intrinsics ────────────────────────────────────
          // Use IntrinsicID instead of the mangled name so we catch all
          // typed variants (llvm.memcpy.p0.p0.i64, llvm.memset.p0.i32, …).
          if (auto *II = dyn_cast<IntrinsicInst>(&I)) {
            Intrinsic::ID IID = II->getIntrinsicID();
            if (IID == Intrinsic::memcpy  ||
                IID == Intrinsic::memset  ||
                IID == Intrinsic::memmove) {
              // For all three: arg0 = dest, arg2 = length.
              Value *Dest = II->getArgOperand(0);
              Value *Len  = II->getArgOperand(2); // may be i32 or i64
              Sites.push_back({II, Dest, Len});
            }
          }
        }
      }

      // Now insert the callback calls, working site by site.
      for (Site &S : Sites) {
        // Place the IRBuilder *after* the instrumented instruction.
        IRBuilder<> Builder(S.InsertAfter->getNextNode());

        // id: compile-time constant
        Value *ID = ConstantInt::get(Int32Ty, SiteID++);

        // ptr: cast destination to opaque ptr if needed (it already is in
        // LLVM 15+ with opaque pointers; bitcast is a no-op in that case).
        Value *Ptr = Builder.CreateBitOrPointerCast(S.Ptr, PtrTy);

        // len: truncate or zero-extend to i32
        Value *Len = Builder.CreateIntCast(S.Len, Int32Ty, /*isSigned=*/false);

        Builder.CreateCall(CB, {ID, Ptr, Len});
      }
    }

    // We added calls → the IR was modified, so we cannot claim all analyses
    // are preserved.
    return PreservedAnalyses::none();
  }

  // Mark the pass as required so it is not skipped when optimisations are
  // disabled (e.g. -O0 pipelines).
  static bool isRequired() { return true; }
};

} // namespace

// ---------------------------------------------------------------------------
// New-PM plugin registration
// ---------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getKdoStorePassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "KdoStorePass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // Register for use with opt -passes="kdo-store"
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "kdo-store") {
                    MPM.addPass(KdoStorePass());
                    return true;
                  }
                  return false;
                });

            // Also inject automatically at the start of every compilation
            // pipeline (mirrors the approach in DataOnly.cpp).
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(KdoStorePass());
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getKdoStorePassPluginInfo();
}
