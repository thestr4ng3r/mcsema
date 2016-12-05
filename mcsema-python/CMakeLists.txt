
cmake_minimum_required(VERSION 2.8)



option(MCSEMA_PYTHON_BUILD_CMAKE "Build mcsema python extension using cmake." OFF)
option(MCSEMA_PYTHON_BUILD_SETUPTOOLS "Build mcsema python extension using setuptools." ON)



find_package(PythonLibs REQUIRED)
find_package(PythonInterp REQUIRED)


set(MCSEMA_EXT_SRC
		mcsemamodule.cpp
		llvm_lifter.cpp
		bin_descend/cfg_recover.cpp
		bin_descend/ExternalFuncMap.cpp)

set(PROTOBUF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/protobuf-2.5.0/src)

set(MCSEMA_EXT_INCLUDE_DIRS
		${CMAKE_CURRENT_BINARY_DIR}/../llvm-3.5/lib/Target/X86
		${CMAKE_CURRENT_SOURCE_DIR}/../llvm-3.5/lib/Target/X86
		${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/peToCFG
		${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/cfgToLLVM
		${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/binary_common
		${CMAKE_CURRENT_SOURCE_DIR}/../llvm-3.5/include
		${CMAKE_CURRENT_BINARY_DIR}/../llvm-3.5/include
		${CMAKE_CURRENT_SOURCE_DIR}/../mc-sema/common
		${Boost_INCLUDE_DIRS}
		${CMAKE_CURRENT_BINARY_DIR}
		${PROTOBUF_INCLUDE_DIR}
		${PROTO_SRCS}
		${PROTO_HDRS}
		${PYTHON_INCLUDE_DIRS})

include_directories(${MCSEMA_EXT_INCLUDE_DIRS})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")





set(ROOT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/..)

set(MCSEMA_EXT_LIBRARY_DIRS
		${Boost_Python_LIBRARY_DIRS}
		${ROOT_BINARY_DIR}/mc-sema/binary_common
		${ROOT_BINARY_DIR}/mc-sema/cfgToLLVM
		${ROOT_BINARY_DIR}/mc-sema/peToCFG
		${ROOT_BINARY_DIR}/llvm-3.5/lib
		${ROOT_BINARY_DIR}/mc-sema/protobuf-cmake/libprotobuf
		${ROOT_BINARY_DIR}/mc-sema/binary_common/pe-parse/parser-library)

set(MCSEMA_EXT_LIBRARIES
		cfgToLLVM
		peToCFG
		binary_common)

set(MCSEMA_EXT_LIBRARIES_WHOLE_ARCHIVE
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
		boost_python-mt-d
		protobuf
		boost_filesystem-mt-d
		boost_system-mt-d
		tinfo)

link_directories(${MCSEMA_EXT_LIBRARY_DIRS})


if(MCSEMA_PYTHON_BUILD_CMAKE)
	add_library(mcsema_ext SHARED ${MCSEMA_EXT_SRC})
	set_target_properties(mcsema_ext PROPERTIES
			OUTPUT_NAME "mcsema"
			PREFIX "")

	target_link_libraries(mcsema_ext ${MCSEMA_EXT_LIBRARIES})
	target_link_libraries(mcsema_ext "-Wl,--whole-archive" ${MCSEMA_EXT_LIBRARIES_WHOLE_ARCHIVE} "-Wl,--no-whole-archive")

	add_dependencies(mcsema_ext binary_common peToCFG cfgToLLVM LLVMX86CodeGen)
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



	set(MCSEMA_EXT_LINK_ARGS "-Wl,--whole-archive")
	foreach(l ${MCSEMA_EXT_LIBRARIES_WHOLE_ARCHIVE})
		list(APPEND MCSEMA_EXT_LINK_ARGS "-l${l}")
	endforeach(l)
	list(APPEND MCSEMA_EXT_LINK_ARGS "-Wl,--no-whole-archive")


	to_python_list(PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/"
			OUTPUT MCSEMA_EXT_SRC_PY
			ENTRIES ${MCSEMA_EXT_SRC})

	to_python_list(OUTPUT MCSEMA_EXT_INCLUDE_DIRS_PY
			ENTRIES ${MCSEMA_EXT_INCLUDE_DIRS})

	to_python_list(OUTPUT MCSEMA_EXT_LIBRARY_DIRS_PY
			ENTRIES ${MCSEMA_EXT_LIBRARY_DIRS})

	to_python_list(OUTPUT MCSEMA_EXT_LIBRARIES_PY
			ENTRIES ${MCSEMA_EXT_LIBRARIES})

	to_python_list(OUTPUT MCSEMA_EXT_LINK_ARGS_PY
			ENTRIES ${MCSEMA_EXT_LINK_ARGS})



	set(SETUP_PY "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in" ${SETUP_PY})



	set(TIMESTAMP_FILE "${CMAKE_CURRENT_BINARY_DIR}/build/timestamp")
	add_custom_command(OUTPUT ${TIMESTAMP_FILE}
			COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} build
			COMMAND ${CMAKE_COMMAND} -E touch ${TIMESTAMP_FILE}
			DEPENDS ${MCSEMA_PYTHON_SRC})

	add_custom_target(mcsema-python ALL DEPENDS ${TIMESTAMP_FILE})

	add_dependencies(mcsema-python boost)
	add_dependencies(bin_descend binary_common peToCFG LLVMX86CodeGen)

	install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install --prefix=${CMAKE_INSTALL_PREFIX})")
endif(MCSEMA_PYTHON_BUILD_SETUPTOOLS)