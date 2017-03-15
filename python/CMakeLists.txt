
cmake_minimum_required(VERSION 2.8)

option(MCSEMA_BUILD_PYTHON "Build mcsema python bindings." OFF)


if(MCSEMA_BUILD_PYTHON)
	find_package(PythonLibs 2.7 REQUIRED)
	find_package(PythonInterp 2.7 REQUIRED)

	find_package(Boost REQUIRED COMPONENTS python)
	include_directories(${Boost_INCLUDE_DIRS})

	set(MCSEMA_PYTHON_SRC
			mcsemamodule.cpp
			lifter.cpp
			lifter.h
			lift.cpp
			lift.h)

	set(MCSEMA_PYTHON_LIFT_SRC
			${MCSEMA_DIR}/mcsema/Arch/Arch.cpp

			${MCSEMA_DIR}/mcsema/Arch/X86/Dispatch.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Lift.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Register.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Util.cpp

			#${MCSEMA_DIR}/mcsema/BC/Lift.cpp
			${MCSEMA_DIR}/mcsema/BC/Util.cpp
			${MCSEMA_DIR}/mcsema/CFG/CFG.cpp
			${MCSEMA_DIR}/generated/CFG.pb.cc

			${MCSEMA_DIR}/mcsema/cfgToLLVM/JumpTables.cpp
			${MCSEMA_DIR}/mcsema/cfgToLLVM/TransExcn.cpp

			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/ADD.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/bitops.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Branches.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/CMOV.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/CMPTEST.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Exchanges.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/fpu.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/INCDECNEG.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Jcc.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Misc.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/MOV.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/MULDIV.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SETcc.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/ShiftRoll.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SSE.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Stack.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/String.cpp
			${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SUB.cpp)

	set(PROTOBUF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/protobuf-2.5.0/src)

	set(MCSEMA_PYTHON_INCLUDE_DIRS
			${LLVM_INCLUDE_DIRS}
			#${LLVM_INSTALL_PREFIX}/llvm/lib/Target/X86
			#${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/cfgToLLVM
			#${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/binary_common
			#${CMAKE_CURRENT_BINARY_DIR}/../mc-sema/binary_common
			#${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/common
			${Boost_INCLUDE_DIRS}
			${CMAKE_CURRENT_BINARY_DIR}
			${PROTOBUF_INCLUDE_DIR}
			${PROTO_SRCS}
			${PROTO_HDRS}
			${PYTHON_INCLUDE_DIRS})

	include_directories(${MCSEMA_PYTHON_INCLUDE_DIRS})

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")


	set(ROOT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/..)

	set(MCSEMA_PYTHON_LIBRARY_DIRS
			${LLVM_LIBRARY_DIRS})

	set(MCSEMA_PYTHON_LIBRARIES_WHOLE_ARCHIVE
			LLVMSupport
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
			LLVMObjCARCOpts
			${PROTOBUF_LIBRARIES}
			#tinfo
			${Boost_FILESYSTEM_LIBRARY}
			${Boost_SYSTEM_LIBRARY}
			${Boost_PYTHON_LIBRARY})



	link_directories(${MCSEMA_PYTHON_LIBRARY_DIRS})

	set(MCSEMA_PYTHON_PACKAGE_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/mcsema)

	file(MAKE_DIRECTORY ${MCSEMA_PYTHON_PACKAGE_BINARY_DIR})
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cfg_ida.py ${MCSEMA_PYTHON_PACKAGE_BINARY_DIR} COPYONLY)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${MCSEMA_PYTHON_PACKAGE_BINARY_DIR} COPYONLY)

	add_library(mcsema-python SHARED ${MCSEMA_PYTHON_SRC} ${MCSEMA_PYTHON_LIFT_SRC})
	set_target_properties(mcsema-python PROPERTIES
			OUTPUT_NAME "mcsema"
			PREFIX ""
			LIBRARY_OUTPUT_DIRECTORY ${MCSEMA_PYTHON_PACKAGE_BINARY_DIR})

	target_link_libraries(mcsema-python "-Wl,--whole-archive" ${MCSEMA_PYTHON_LIBRARIES_WHOLE_ARCHIVE} "-Wl,--no-whole-archive")


	execute_process(COMMAND "${PYTHON_EXECUTABLE}" -c "if True: from distutils import sysconfig as sc; print(sc.get_python_lib(prefix='', plat_specific=True))"
			OUTPUT_VARIABLE PYTHON_SITE_PACKAGES_DIR
			OUTPUT_STRIP_TRAILING_WHITESPACE)

	set(PYTHON_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/${PYTHON_SITE_PACKAGES_DIR}
			CACHE PATH "Path to site-packages or any other directory to install python bindings.")

	install(DIRECTORY ${MCSEMA_PYTHON_PACKAGE_BINARY_DIR}
			DESTINATION ${PYTHON_INSTALL_DIR})
endif(MCSEMA_BUILD_PYTHON)


