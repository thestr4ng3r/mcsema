add_subdirectory(pe-parse)

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS CFG.proto)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_INCLUDE_DIRS})

add_library(binary_common ${PROTO_SRCS} ${PROTO_HDRS} bincomm.cpp LLVMObjectTarget.cpp ELFTarget.cpp PETarget.cpp COFFTarget.cpp)
add_dependencies(binary_common pe-parser-library)
target_link_libraries(binary_common pe-parser-library)
