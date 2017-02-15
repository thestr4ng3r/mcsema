

add_subdirectory(CFG)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/CFG)
include_directories(${MCSEMA_PROTOBUF_GEN_DIR})



set(MCSEMA_SRC
		Lift.cpp
		Arch/Arch.cpp
		Arch/X86/Register.cpp
		Arch/X86/Dispatch.cpp
		BC/Util.cpp
		CFG/CFG.cpp

		${MCSEMA_PROTOBUF_GEN_DIR}/CFG.pb.cc

		cfgToLLVM/raiseX86.cpp
		cfgToLLVM/x86Helpers.cpp
		cfgToLLVM/x86_64Helpers.cpp
		cfgToLLVM/x86Instrs.cpp
		cfgToLLVM/ArchOps.cpp
		cfgToLLVM/JumpTables.cpp

		cfgToLLVM/TransExcn.cpp

		cfgToLLVM/x86Instrs_ADD.cpp
		cfgToLLVM/x86Instrs_bitops.cpp
		cfgToLLVM/x86Instrs_Branches.cpp
		cfgToLLVM/x86Instrs_CMOV.cpp
		cfgToLLVM/x86Instrs_CMPTEST.cpp
		cfgToLLVM/x86Instrs_Exchanges.cpp
		cfgToLLVM/x86Instrs_fpu.cpp
		cfgToLLVM/x86Instrs_INCDECNEG.cpp
		cfgToLLVM/x86Instrs_Jcc.cpp
		cfgToLLVM/x86Instrs_Misc.cpp
		cfgToLLVM/x86Instrs_MOV.cpp
		cfgToLLVM/x86Instrs_MULDIV.cpp
		cfgToLLVM/x86Instrs_SETcc.cpp
		cfgToLLVM/x86Instrs_ShiftRoll.cpp
		cfgToLLVM/x86Instrs_SSE.cpp
		cfgToLLVM/x86Instrs_Stack.cpp
		cfgToLLVM/x86Instrs_String.cpp
		cfgToLLVM/x86Instrs_SUB.cpp)


# Make sure we can find the mcsema headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/binary_common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cfgToLLVM)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/peToCFG)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cfgToLLVM)

add_executable(mcsema-lift ${MCSEMA_SRC})

add_dependencies(mcsema-lift cfg-protobuf)

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