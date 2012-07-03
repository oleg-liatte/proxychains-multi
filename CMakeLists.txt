project(proxychains-ng)
cmake_minimum_required(VERSION 2.8)

find_package(BISON)
find_package(FLEX)

# BISON_TARGET(config_parser config.y ${CMAKE_CURRENT_BINARY_DIR}/config_parser.cpp COMPILE_FLAGS "--debug --verbose")
# FLEX_TARGET(config_lexer config.l  ${CMAKE_CURRENT_BINARY_DIR}/config_lexer.cpp COMPILE_FLAGS "--debug")

BISON_TARGET(config_parser config.y ${CMAKE_CURRENT_BINARY_DIR}/config_parser.cpp)
FLEX_TARGET(config_lexer config.l  ${CMAKE_CURRENT_BINARY_DIR}/config_lexer.cpp)

ADD_FLEX_BISON_DEPENDENCY(config_lexer config_parser)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB SOURCES *.cpp)

set(SOURCES
    ${SOURCES}
    ${BISON_config_parser_OUTPUTS}
    ${FLEX_config_lexer_OUTPUTS}
)

set(CMAKE_CXX_FLAGS -Wall)

add_library(proxychains-ng SHARED ${SOURCES})

target_link_libraries(proxychains-ng
    dl
)
