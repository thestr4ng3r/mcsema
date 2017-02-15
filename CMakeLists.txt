# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

cmake_minimum_required(VERSION 3.1)
project(mcsema)

set (CMAKE_CXX_STANDARD 11)

if(WIN32)
SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

set(MCSEMA_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(MCSEMA_GEN_DIR "${MCSEMA_DIR}/generated")

# Get protobuf
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})

# Get custom LLVM
find_package(LLVM 3.8 REQUIRED)
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
include_directories(${LLVM_INSTALL_PREFIX}/include/llvm/lib/Target/X86)

include_directories(${MCSEMA_DIR})
include_directories(${MCSEMA_BUILD_DIR}/include)
include_directories(${MCSEMA_GEN_DIR})

# Make sure we can find the mcsema headers.
include_directories(${MCSEMA_DIR}/mcsema)
include_directories(${MCSEMA_DIR}/mcsema/binary_common)
include_directories(${MCSEMA_DIR}/mcsema/cfgToLLVM)
include_directories(${MCSEMA_DIR}/mcsema/common)
include_directories(${MCSEMA_DIR}/mcsema/peToCFG)
include_directories(${MCSEMA_DIR}/mcsema/cfgToLLVM)

add_compile_options(
  -x c++
  -g3
  -O0
#  -std=gnu++11
#  -fno-rtti
#  -DGOOGLE_PROTOBUF_NO_RTTI
	)

add_executable(mcsema-lift
  ${MCSEMA_DIR}/mcsema/Lift.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Arch.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Register.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Dispatch.cpp
  ${MCSEMA_DIR}/mcsema/BC/Util.cpp
  ${MCSEMA_DIR}/mcsema/CFG/CFG.cpp
  ${MCSEMA_DIR}/generated/CFG.pb.cc

  ${MCSEMA_DIR}/mcsema/cfgToLLVM/raiseX86.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Helpers.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86_64Helpers.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/ArchOps.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/JumpTables.cpp

  ${MCSEMA_DIR}/mcsema/cfgToLLVM/TransExcn.cpp

  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_ADD.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_bitops.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_Branches.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_CMOV.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_CMPTEST.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_Exchanges.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_fpu.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_INCDECNEG.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_Jcc.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_Misc.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_MOV.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_MULDIV.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_SETcc.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_ShiftRoll.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_SSE.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_Stack.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_String.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/x86Instrs_SUB.cpp)

set_target_properties(mcsema-lift PROPERTIES COMPILE_FLAGS "-fno-rtti -DGOOGLE_PROTOBUF_NO_RTTI")

target_link_libraries(mcsema-lift
  protobuf
  LLVMBitReader
  LLVMBitWriter
  LLVMMCDisassembler
  LLVMX86Disassembler
  LLVMX86AsmParser
  LLVMX86CodeGen
  LLVMSelectionDAG
  LLVMAsmPrinter
  LLVMX86Desc
  LLVMX86Info
  LLVMX86AsmPrinter
  LLVMX86Utils
  LLVMipo
  LLVMTransformUtils
  LLVMScalarOpts
  LLVMInstrumentation
  LLVMObjCARCOpts)

install(
  TARGETS mcsema-lift
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib)

add_subdirectory(python)