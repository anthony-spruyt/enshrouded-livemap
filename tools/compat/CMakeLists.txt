cmake_minimum_required(VERSION 3.28)

# Standalone on Linux (the root project needs the Windows toolchain); the root adds it as a subdirectory on Windows.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(livemap_compat LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    enable_testing()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

if(NOT TARGET Zydis)
    set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
    set(ZYDIS_FEATURE_ENCODER OFF CACHE BOOL "" FORCE)
    set(ZYDIS_FEATURE_FORMATTER OFF CACHE BOOL "" FORCE)
    include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/zydis.cmake")
    FetchContent_MakeAvailable(Zydis)
endif()

add_library(livemap_compat_core STATIC
    src/analyze.cpp
    src/builds.cpp
    src/callbacks.cpp
    src/check.cpp
    src/cli.cpp
    src/disasm.cpp
    src/hooks.cpp
    src/json.cpp
    src/liveness.cpp
    src/pe.cpp
    src/report.cpp
    src/sha256.cpp
    src/signature.cpp
    src/sites.cpp
)
target_include_directories(livemap_compat_core PUBLIC src)
target_link_libraries(livemap_compat_core PUBLIC Zydis)
if(MSVC)
    target_compile_options(livemap_compat_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(livemap_compat_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(livemap_compat src/main.cpp)
target_link_libraries(livemap_compat PRIVATE livemap_compat_core)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(livemap_compat PRIVATE -static-pie)
endif()

set(LIVEMAP_COMPAT_TESTS "${CMAKE_CURRENT_LIST_DIR}/../../tests/compat")
foreach(name IN ITEMS analyze builds callbacks check cli disasm json liveness pe report sha256 signature sites)
    add_executable(compat_${name}_test "${LIVEMAP_COMPAT_TESTS}/${name}_test.cpp")
    target_link_libraries(compat_${name}_test PRIVATE livemap_compat_core)
    target_include_directories(compat_${name}_test PRIVATE "${LIVEMAP_COMPAT_TESTS}")
    add_test(NAME compat_${name} COMMAND compat_${name}_test)
endforeach()
foreach(name IN ITEMS builds callbacks json)
    target_compile_definitions(compat_${name}_test PRIVATE LIVEMAP_BUILDS_JSON="${CMAKE_CURRENT_LIST_DIR}/../../data/builds.json")
endforeach()
target_compile_definitions(compat_callbacks_test PRIVATE LIVEMAP_SOURCE_DIR="${CMAKE_CURRENT_LIST_DIR}/../../src")
target_include_directories(compat_callbacks_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../..)
