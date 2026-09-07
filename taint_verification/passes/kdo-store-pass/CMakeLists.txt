set(LLVM_LIBRARY_OUTPUT_INTDIR ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_CFG_INTDIR}/${LLVM_LIBDIR_SUFFIX})

add_llvm_library(LLVMKdoStorePass MODULE
    KdoStorePass.cpp
    HookHash.cpp
)

include_directories(.)

find_package(OpenSSL REQUIRED)
target_link_libraries(LLVMKdoStorePass PRIVATE OpenSSL::SSL OpenSSL::Crypto)
