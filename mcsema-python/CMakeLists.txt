
cmake_minimum_required(VERSION 2.8)

find_package(PythonLibs REQUIRED)

include_directories(${Boost_INCLUDE_DIRS}
		${PYTHON_INCLUDE_DIRS})

set(MCSEMA_EXT_SRC
		mcsemamodule.cpp
		test.cpp)

add_library(mcsema_ext SHARED ${MCSEMA_EXT_SRC})
target_link_libraries(mcsema_ext ${Boost_LIBRARIES})

set_target_properties(mcsema_ext PROPERTIES PREFIX "")