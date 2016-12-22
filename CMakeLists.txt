project(mc-sema)
cmake_minimum_required(VERSION 2.8)

if(WIN32)
SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)


find_package(Boost REQUIRED
        COMPONENTS filesystem date_time program_options system thread python)

include_directories(${Boost_INCLUDE_DIRS})


add_subdirectory(llvm-3.5)
add_subdirectory(mc-sema)
add_subdirectory(mcsema-python)
