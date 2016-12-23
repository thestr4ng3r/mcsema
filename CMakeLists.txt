project(mc-sema)
cmake_minimum_required(VERSION 2.8)

if(WIN32)
SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)


find_package(Boost REQUIRED COMPONENTS filesystem date_time program_options system thread python)
include_directories(${Boost_INCLUDE_DIRS})

find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})

find_package(LLVM REQUIRED)
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
include_directories(${LLVM_INSTALL_PREFIX}/include/llvm/lib/Target/X86)



add_subdirectory(mc-sema)
add_subdirectory(mcsema-python)
