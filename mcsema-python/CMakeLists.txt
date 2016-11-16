
cmake_minimum_required(VERSION 2.8)

find_package(PythonLibs REQUIRED)
find_package(PythonInterp REQUIRED)

include_directories(${Boost_INCLUDE_DIRS}
		${PYTHON_INCLUDE_DIRS})

set(MCSEMA_EXT_SRC
		mcsemamodule.cpp
		test.cpp)

#add_library(mcsema_ext SHARED ${MCSEMA_EXT_SRC})
#target_link_libraries(mcsema_ext ${Boost_Python_LIBRARIES})

#set_target_properties(mcsema_ext PROPERTIES PREFIX "")



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
		ENTRIES ${Boost_INCLUDE_DIRS})

to_python_list(OUTPUT MCSEMA_EXT_LIBRARY_DIRS_PY
		ENTRIES ${Boost_Python_LIBRARY_DIRS})

to_python_list(OUTPUT MCSEMA_EXT_LIBRARIES_PY
		ENTRIES ${Boost_Python_LIBRARIES})


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