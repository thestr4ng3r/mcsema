# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

cmake_minimum_required(VERSION 3.1)
project(mcsema)

set (CMAKE_CXX_STANDARD 11)

if(WIN32)
SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

set(MCSEMA_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(MCSEMA_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(MCSEMA_GEN_DIR "${MCSEMA_DIR}/generated")

# Get protobuf
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})

# Get custom LLVM
find_package(LLVM 3.8 REQUIRED)
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
include_directories(${LLVM_INSTALL_PREFIX}/include/llvm/lib/Target/X86)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${MCSEMA_BUILD_DIR}/include)


# TODO: replace with cmake stuff
add_compile_options(
  -x c++
  -g3
  -O0)

add_subdirectory(mcsema)
add_subdirectory(python)