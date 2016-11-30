
cmake_minimum_required(VERSION 2.8)

find_package(PythonLibs REQUIRED)
find_package(PythonInterp REQUIRED)


set(MCSEMA_EXT_SRC
		mcsemamodule.cpp
		test.cpp
		llvm_lifter.cpp
		bin_descend_py.cpp
		cfg_recover.cpp
		ExternalFuncMap.cpp
		)

add_library(mcsema_ext SHARED EXCLUDE_FROM_ALL ${MCSEMA_EXT_SRC})

#set_target_properties(mcsema_ext PROPERTIES PREFIX "")

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

#include_directories()



set(ROOT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/..)

set(MCSEMA_EXT_LIBRARY_DIRS
		${Boost_Python_LIBRARY_DIRS}
		${ROOT_BINARY_DIR}/mc-sema/binary_common
		${ROOT_BINARY_DIR}/mc-sema/cfgToLLVM
		${ROOT_BINARY_DIR}/mc-sema/peToCFG
		${ROOT_BINARY_DIR}/llvm-3.5/lib
		${ROOT_BINARY_DIR}/mc-sema/protobuf-cmake/libprotobuf)

set(MCSEMA_EXT_LIBRARIES
		binary_common cfgToLLVM peToCFG LLVMBitReader LLVMBitWriter
		LLVMMCDisassembler LLVMX86Disassembler LLVMX86AsmParser LLVMX86CodeGen
		LLVMSelectionDAG LLVMAsmPrinter LLVMX86Desc LLVMX86Info
		LLVMX86AsmPrinter LLVMX86Utils ${Boost_LIBRARIES} protobuf
		${Boost_Python_LIBRARIES})

link_directories(${CMAKE_CURRENT_BINARY_DIR}/../../lib)

target_link_libraries(mcsema_ext ${MCSEMA_EXT_LIBRARIES})

add_dependencies(mcsema_ext binary_common peToCFG cfgToLLVM LLVMX86CodeGen)








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




to_python_list(PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/"
		OUTPUT MCSEMA_EXT_SRC_PY
		ENTRIES ${MCSEMA_EXT_SRC})

to_python_list(OUTPUT MCSEMA_EXT_INCLUDE_DIRS_PY
		ENTRIES ${MCSEMA_EXT_INCLUDE_DIRS})

to_python_list(OUTPUT MCSEMA_EXT_LIBRARY_DIRS_PY
		ENTRIES ${MCSEMA_EXT_LIBRARY_DIRS})

to_python_list(OUTPUT MCSEMA_EXT_LIBRARIES_PY
		ENTRIES ${MCSEMA_EXT_LIBRARIES})


set(SETUP_PY "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in" ${SETUP_PY})



set(TIMESTAMP_FILE "${CMAKE_CURRENT_BINARY_DIR}/build/timestamp")
add_custom_command(OUTPUT ${TIMESTAMP_FILE}
		COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} build
		COMMAND ${CMAKE_COMMAND} -E touch ${TIMESTAMP_FILE}
		DEPENDS ${MCSEMA_PYTHON_SRC})

add_custom_target(mcsema-python ALL DEPENDS ${TIMESTAMP_FILE})
add_dependencies(mcsema-python boost)

install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install --prefix=${CMAKE_INSTALL_PREFIX})")