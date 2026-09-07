// KdoStorePass.cpp
//
// LLVM instrumentation pass that inserts a call to
//
//   void kdo_store_callback(int id, void *ptr, int len)
//
// immediately *after* every store instruction and after every call to the
// llvm.memcpy / llvm.memset / llvm.memmove memory intrinsics.
//
// ── ID assignment (three-step, matching DataOnly.cpp) ─────────────────────
//
//   Step 1 – buildHookHash(I)
//     Produce a human-readable descriptor string from the instruction's debug
//     location, enclosing function name, opcode, result type, and operand
//     types/values.
//
//   Step 2 – get_hook_id_full(hook_hash)
//     SHA-256 the descriptor and hex-encode all 32 bytes → a 64-character
//     collision-free string that uniquely identifies the site.
//
//   Step 3 – DB lookup
//     The sorted DB file (-kdo-store-db) contains one hex ID per line.
//     The 1-based line number of the matching entry is the integer passed to
//     the callback.  This gives a compact, stable, runtime-cheap id.
//
// ── Missing IDs ───────────────────────────────────────────────────────────
//
//   If an ID is not found in the DB:
//     • The site is NOT instrumented (no callback inserted).
//     • A warning is printed to stderr.
//     • The hex ID + newline is appended to <db-file>.new using a single
//       O_APPEND write() call, which is atomically safe across both threads
//       and processes on Linux (each write() < PIPE_BUF = 4096 bytes; a hex
//       ID line is 65 bytes).
//
//   After a build that emits new IDs, merge them into the DB offline:
//
//     sort -u <db-file>.new <db-file> > db-merged.txt && mv db-merged.txt <db-file>
//
//   Then rebuild.  The DB is read-only during compilation; only the .new log
//   is ever written during a build.
//
// ── CLI options ───────────────────────────────────────────────────────────
//   -kdo-store-db=<path>   Sorted DB file (one hex SHA-256 per line).
//                          If empty the pass runs but instruments nothing
//                          (all sites are treated as missing).

#include "hash_hook_id.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include <fcntl.h>    // open, O_WRONLY, O_CREAT, O_APPEND
#include <unistd.h>   // write, close
#include <fstream>
#include <map>
#include <optional>
#include <string>

using namespace llvm;

// ---------------------------------------------------------------------------
// CLI options
// ---------------------------------------------------------------------------
static cl::opt<std::string> DbFile(
    "kdo-store-db",
    cl::desc("KdoStorePass: path to sorted DB file (one hex SHA-256 per line)"),
    cl::Hidden, cl::init(""));

// ---------------------------------------------------------------------------
// loadDb – read the sorted DB file into a map: hex_id → 1-based line number.
// ---------------------------------------------------------------------------
static std::map<std::string, uint32_t> loadDb(const std::string &Path) {
  std::map<std::string, uint32_t> Db;
  if (Path.empty())
    return Db;

  std::ifstream In(Path);
  if (!In.is_open()) {
    errs() << "[KdoStorePass] warning: cannot open DB file: " << Path << "\n";
    return Db;
  }

  std::string Line;
  uint32_t LineNo = 0;
  while (std::getline(In, Line)) {
    ++LineNo;
    if (!Line.empty())
      Db[Line] = LineNo;
  }
  return Db;
}

// ---------------------------------------------------------------------------
// appendNewId – atomically append HexId + '\n' to <DbPath>.new.
//
// Uses O_APPEND + a single write() call.  POSIX guarantees that write() to
// an O_APPEND file is atomic w.r.t. the offset update for writes smaller than
// PIPE_BUF (4096 bytes on Linux).  A 64-char hex ID + newline = 65 bytes,
// well within that limit — so concurrent appenders from multiple threads or
// processes will never interleave their lines.
// ---------------------------------------------------------------------------
static void appendNewId(const std::string &DbPath, const std::string &HexId) {
  if (DbPath.empty())
    return;

  std::string NewPath = DbPath + ".new";
  int Fd = open(NewPath.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (Fd < 0) {
    errs() << "[KdoStorePass] warning: cannot open new-IDs file: "
           << NewPath << "\n";
    return;
  }

  std::string Line = HexId + "\n";
  // Single write() — atomic under O_APPEND for sizes < PIPE_BUF.
  (void)write(Fd, Line.c_str(), Line.size());
  close(Fd);
}

// ---------------------------------------------------------------------------
// getOrInsertCallback – lazily declare kdo_store_callback in the module.
//
//   void kdo_store_callback(int id, void *ptr, int len)
//
// id   – 1-based line number from the DB (i32)
// ptr  – destination address (opaque pointer)
// len  – byte width of the write (i32)
// ---------------------------------------------------------------------------
static FunctionCallee getOrInsertCallback(Module &M) {
  LLVMContext &Ctx = M.getContext();
  Type *VoidTy  = Type::getVoidTy(Ctx);
  Type *Int32Ty = Type::getInt32Ty(Ctx);
  Type *PtrTy   = PointerType::getUnqual(Ctx);

  FunctionType *FT = FunctionType::get(VoidTy,
                                       {Int32Ty, PtrTy, Int32Ty},
                                       /*isVarArg=*/false);
  return M.getOrInsertFunction("kdo_store_callback", FT);
}

// ---------------------------------------------------------------------------
// KdoStorePass
// ---------------------------------------------------------------------------
namespace {

struct KdoStorePass : PassInfoMixin<KdoStorePass> {

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    const DataLayout &DL = M.getDataLayout();
    LLVMContext &Ctx     = M.getContext();
    FunctionCallee CB    = getOrInsertCallback(M);

    Type *Int32Ty = Type::getInt32Ty(Ctx);
    Type *PtrTy   = PointerType::getUnqual(Ctx);

    // Load the DB once per module visit.
    std::map<std::string, uint32_t> Db = loadDb(DbFile);

    // lookupId – shared three-step ID resolution for any instruction.
    // Returns the 1-based DB line number, or nullopt if the ID is missing
    // (in which case it also emits a warning and appends to the .new log).
    auto lookupId = [&](const Instruction &I) -> std::optional<uint32_t> {
      // Step 1 – descriptor string
      std::string HookHash = buildHookHash(I);
      // Step 2 – full 64-char hex SHA-256
      std::string HexId    = get_hook_id_full(HookHash);
      // Step 3 – DB lookup
      auto It = Db.find(HexId);
      if (It != Db.end())
        return It->second;

      errs() << "[KdoStorePass] warning: ID not in DB, skipping site: "
             << HexId << "\n";
      // // Source location (requires debug info; silent if unavailable).
      // if (const DebugLoc &DL = I.getDebugLoc()) {
      //   errs() << "  source: " << DL->getFilename()
      //          << ":" << DL->getLine()
      //          << ":" << DL->getColumn() << "\n";
      // }
      // // IR instruction text.
      // errs() << "  IR:     ";
      // I.print(errs(), /*IsForDebug=*/true);
      // errs() << "\n";
      appendNewId(DbFile, HexId);
      return std::nullopt;
    };

    // Collect instrumentation points first, then apply, so we never
    // invalidate the iterator while walking the instruction list.
    struct Site {
      Instruction *InsertAfter;
      Value       *Ptr;
      Value       *Len;
      uint32_t     DbLineNo; // 1-based position in the DB file → callback id
    };

    bool Modified = false;

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      if (F.getName() == "kdo_store_callback")
        continue;

      SmallVector<Site, 16> Sites;

      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {

          // ── StoreInst ───────────────────────────────────────────────────
          if (auto *SI = dyn_cast<StoreInst>(&I)) {
            auto ID = lookupId(*SI);
            if (!ID)
              continue;

            Type    *StoredTy = SI->getValueOperand()->getType();
            TypeSize TS       = DL.getTypeStoreSize(StoredTy);
            Value   *LenVal   = ConstantInt::get(
                Int32Ty, static_cast<uint32_t>(TS.getFixedValue()));
            Sites.push_back({SI, SI->getPointerOperand(), LenVal, *ID});
            continue;
          }

          // ── memcpy / memset / memmove intrinsics ────────────────────────
          if (auto *II = dyn_cast<IntrinsicInst>(&I)) {
            Intrinsic::ID IID = II->getIntrinsicID();
            if (IID != Intrinsic::memcpy &&
                IID != Intrinsic::memset &&
                IID != Intrinsic::memmove)
              continue;

            auto ID = lookupId(*II);
            if (!ID)
              continue;

            Sites.push_back({II, II->getArgOperand(0), II->getArgOperand(2), *ID});
          }
        }
      }

      for (Site &S : Sites) {
        IRBuilder<> Builder(S.InsertAfter->getNextNode());

        Value *ID  = ConstantInt::get(Int32Ty, S.DbLineNo);
        Value *Ptr = Builder.CreateBitOrPointerCast(S.Ptr, PtrTy);
        Value *Len = Builder.CreateIntCast(S.Len, Int32Ty, /*isSigned=*/false);

        Builder.CreateCall(CB, {ID, Ptr, Len});
        Modified = true;
      }
    }

    return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  static bool isRequired() { return true; }
};

} // namespace

// ---------------------------------------------------------------------------
// New-PM plugin registration
// ---------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getKdoStorePassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "KdoStorePass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "kdo-store") {
                    MPM.addPass(KdoStorePass());
                    return true;
                  }
                  return false;
                });

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
