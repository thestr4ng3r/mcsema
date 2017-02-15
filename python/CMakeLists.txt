
cmake_minimum_required(VERSION 2.8)

option(MCSEMA_BUILD_PYTHON "Build mcsema python bindings." OFF)


if(MCSEMA_BUILD_PYTHON)
	find_package(PythonLibs 2.7 REQUIRED)
	find_package(PythonInterp 2.7 REQUIRED)

	find_package(Boost REQUIRED COMPONENTS python)
	include_directories(${Boost_INCLUDE_DIRS})

	set(BIN_DESCEND_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/bin_descend")
	include_directories(${BIN_DESCEND_SRC_DIR})

	set(MCSEMA_PYTHON_SRC
			mcsemamodule.cpp
			cfg_to_llvm.cpp
			cfg_to_llvm.h
			mcsema_init.cpp
			mcsema_init.h)

	set(PROTOBUF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/protobuf-2.5.0/src)

	set(MCSEMA_PYTHON_INCLUDE_DIRS
			${LLVM_INCLUDE_DIRS}
			${LLVM_INSTALL_PREFIX}/llvm/lib/Target/X86
			${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/peToCFG
			${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/cfgToLLVM
			${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/binary_common
			${CMAKE_CURRENT_BINARY_DIR}/../mc-sema/binary_common
			${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/common
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
			${ROOT_BINARY_DIR}/mc-sema/binary_common
			${ROOT_BINARY_DIR}/mc-sema/cfgToLLVM
			${ROOT_BINARY_DIR}/mc-sema/peToCFG
			${LLVM_LIBRARY_DIRS})

	set(MCSEMA_PYTHON_LIBRARIES
			cfgToLLVM
			peToCFG
			binary_common)

	set(MCSEMA_PYTHON_LIBRARIES_WHOLE_ARCHIVE
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

	add_library(mcsema-python SHARED ${MCSEMA_PYTHON_SRC})
	set_target_properties(mcsema-python PROPERTIES
			OUTPUT_NAME "mcsema"
			PREFIX ""
			LIBRARY_OUTPUT_DIRECTORY ${MCSEMA_PYTHON_PACKAGE_BINARY_DIR})

	target_link_libraries(mcsema-python ${MCSEMA_PYTHON_LIBRARIES})
	target_link_libraries(mcsema-python "-Wl,--whole-archive" ${MCSEMA_PYTHON_LIBRARIES_WHOLE_ARCHIVE} "-Wl,--no-whole-archive")


	execute_process(COMMAND "${PYTHON_EXECUTABLE}" -c "if True: from distutils import sysconfig as sc; print(sc.get_python_lib(prefix='', plat_specific=True))"
			OUTPUT_VARIABLE PYTHON_SITE_PACKAGES_DIR
			OUTPUT_STRIP_TRAILING_WHITESPACE)

	set(PYTHON_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/${PYTHON_SITE_PACKAGES_DIR}
			CACHE PATH "Path to site-packages or any other directory to install python bindings.")

	install(DIRECTORY ${MCSEMA_PYTHON_PACKAGE_BINARY_DIR}
			DESTINATION ${PYTHON_INSTALL_DIR})
endif(MCSEMA_BUILD_PYTHON)


