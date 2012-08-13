project(proxychains-ng)
cmake_minimum_required(VERSION 2.8)

option(USE_THREADS "Enable thread-safety" ON)
if(USE_THREADS)
    add_definitions(-DUSE_THREADS)
endif()

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

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

add_library(proxychains-ng SHARED ${SOURCES})
set_target_properties(proxychains-ng
    PROPERTIES VERSION "1.0"
    SOVERSION "1"
)

if(USE_THREADS)
    set(THREAD_LIBS "pthread")
else()
    set(THREAD_LIBS "")
endif()

target_link_libraries(proxychains-ng
    dl
    ${THREAD_LIBS}
)

install(TARGETS proxychains-ng DESTINATION /usr/lib)
install(PROGRAMS proxychains-ng proxyresolv-ng DESTINATION /usr/bin)
install(FILES proxychains-ng.conf.skel RENAME proxychains-ng.conf DESTINATION /etc)
