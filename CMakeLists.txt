cmake_minimum_required(VERSION 3.16)
project(xinput9_1_0 C CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(SOURCES src/dllmain.cpp)

add_library(xinput9_1_0 SHARED ${SOURCES})

target_link_options(xinput9_1_0 PRIVATE /DEF:${CMAKE_SOURCE_DIR}/xinput9_1_0.def)

target_link_libraries(xinput9_1_0 PRIVATE winhttp wininet)

target_compile_definitions(xinput9_1_0 PRIVATE NDEBUG _WINDOWS _USRDLL)

target_compile_options(xinput9_1_0 PRIVATE /O2 /MT /W3)

set(CMAKE_GENERATOR_PLATFORM Win32)
