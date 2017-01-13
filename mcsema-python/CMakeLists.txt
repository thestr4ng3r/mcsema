
cmake_minimum_required(VERSION 2.8)



option(MCSEMA_PYTHON_BUILD_CMAKE "Build mcsema python extension using cmake." ON)
option(MCSEMA_PYTHON_BUILD_SETUPTOOLS "Build mcsema python extension using setuptools." OFF)




find_package(PythonLibs 2.7 REQUIRED)
find_package(PythonInterp 2.7 REQUIRED)

find_package(Boost REQUIRED COMPONENTS python)
include_directories(${Boost_INCLUDE_DIRS})

set(BIN_DESCEND_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/bin_descend")
include_directories(${BIN_DESCEND_SRC_DIR})

set(MCSEMA_PYTHON_SRC
		mcsemamodule.cpp
		${BIN_DESCEND_SRC_DIR}/cfg_recover.cpp
		${BIN_DESCEND_SRC_DIR}/ExternalFuncMap.cpp
		bin_descend.cpp
		bin_descend.h
		cfg_to_llvm.cpp
		cfg_to_llvm.h mcsema_init.cpp mcsema_init.h)

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
		pe-parser-library
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
		LLVMSupport
		LLVMObject
		LLVMMC
		LLVMCore
		LLVMMCParser
		LLVMCodeGen
		LLVMTarget
		LLVMAnalysis
		LLVMTransformUtils
		LLVMipa
		LLVMipo
		LLVMObjCARCOpts
		LLVMInstrumentation
		LLVMScalarOpts
		LLVMInstCombine
		${PROTOBUF_LIBRARIES}
		tinfo
		${Boost_FILESYSTEM_LIBRARY}
		${Boost_SYSTEM_LIBRARY}
		${Boost_PYTHON_LIBRARY})

link_directories(${MCSEMA_PYTHON_LIBRARY_DIRS})


add_custom_target(
		cfg_ida_py ALL
		${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/cfg_ida.py ${CMAKE_CURRENT_BINARY_DIR}/cfg_ida.py
		SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/cfg_ida.py
)

if(MCSEMA_PYTHON_BUILD_CMAKE)
	add_library(mcsema-python SHARED ${MCSEMA_PYTHON_SRC})
	set_target_properties(mcsema-python PROPERTIES
			OUTPUT_NAME "mcsema"
			PREFIX "")

	target_link_libraries(mcsema-python ${MCSEMA_PYTHON_LIBRARIES})
	target_link_libraries(mcsema-python "-Wl,--whole-archive" ${MCSEMA_PYTHON_LIBRARIES_WHOLE_ARCHIVE} "-Wl,--no-whole-archive")

	add_dependencies(mcsema-python binary_common peToCFG cfgToLLVM LLVMX86CodeGen cfg_ida_py)
endif(MCSEMA_PYTHON_BUILD_CMAKE)









if(MCSEMA_PYTHON_BUILD_SETUPTOOLS)
	# generate setup.py

	function(to_python_list)
		set(one_value_args PREFIX OUTPUT)
		set(multi_value_args ENTRIES)
		cmake_parse_arguments(TO_PY "" "${one_value_args}" "${multi_value_args}" ${ARGN})

		if(TO_PY_ENTRIES)
			string(REPLACE
					";"
					"\", \"${TO_PY_PREFIX}"
					${TO_PY_OUTPUT}
					"${TO_PY_ENTRIES}")
			set(${TO_PY_OUTPUT} "\"${TO_PY_PREFIX}${${TO_PY_OUTPUT}}\"" PARENT_SCOPE)
		else()
			set(${TO_PY_OUTPUT} "" PARENT_SCOPE)
		endif()
	endfunction(to_python_list)



	set(MCSEMA_PYTHON_LINK_ARGS "-Wl,--whole-archive")
	foreach(l ${MCSEMA_PYTHON_LIBRARIES_WHOLE_ARCHIVE})
		list(APPEND MCSEMA_PYTHON_LINK_ARGS "-l${l}")
	endforeach(l)
	list(APPEND MCSEMA_PYTHON_LINK_ARGS "-Wl,--no-whole-archive")


	to_python_list(PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/"
			OUTPUT MCSEMA_PYTHON_SRC_PY
			ENTRIES ${MCSEMA_PYTHON_SRC})

	to_python_list(OUTPUT MCSEMA_PYTHON_INCLUDE_DIRS_PY
			ENTRIES ${MCSEMA_PYTHON_INCLUDE_DIRS})

	to_python_list(OUTPUT MCSEMA_PYTHON_LIBRARY_DIRS_PY
			ENTRIES ${MCSEMA_PYTHON_LIBRARY_DIRS})

	to_python_list(OUTPUT MCSEMA_PYTHON_LIBRARIES_PY
			ENTRIES ${MCSEMA_PYTHON_LIBRARIES})

	to_python_list(OUTPUT MCSEMA_PYTHON_LINK_ARGS_PY
			ENTRIES ${MCSEMA_PYTHON_LINK_ARGS})



	set(SETUP_PY "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in" ${SETUP_PY})



	set(TIMESTAMP_FILE "${CMAKE_CURRENT_BINARY_DIR}/build/timestamp")
	add_custom_command(OUTPUT ${TIMESTAMP_FILE}
			COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} build
			COMMAND ${CMAKE_COMMAND} -E touch ${TIMESTAMP_FILE}
			DEPENDS ${MCSEMA_PYTHON_SRC})

	add_custom_target(mcsema-python-setuptools ALL DEPENDS ${TIMESTAMP_FILE})

	install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install --prefix=${CMAKE_INSTALL_PREFIX})")
endif(MCSEMA_PYTHON_BUILD_SETUPTOOLS)