project(proxychains-multi)
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

add_library(proxychains-multi SHARED ${SOURCES})
set_target_properties(proxychains-multi
    PROPERTIES VERSION "1.0"
    SOVERSION "1"
)

if(USE_THREADS)
    set(THREAD_LIBS "pthread")
else()
    set(THREAD_LIBS "")
endif()

target_link_libraries(proxychains-multi
    dl
    ${THREAD_LIBS}
)

install(TARGETS proxychains-multi DESTINATION /usr/lib)
install(PROGRAMS proxychains-multi proxyresolv-multi DESTINATION /usr/bin)
install(FILES proxychains-multi.conf.skel RENAME proxychains-multi.conf DESTINATION /etc)
