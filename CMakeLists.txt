cmake_minimum_required(VERSION 3.20.0)
set(CMAKE_CXX_STANDARD 20)
project(soteria VERSION 1.0)
configure_file(include/core/version.h.in include/core/version.h)

cmake_policy(SET CMP0167 NEW)
find_package(Boost REQUIRED COMPONENTS filesystem program_options iostreams)
find_package(OpenSSL REQUIRED)

include(FetchContent)

FetchContent_Declare(
  catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.4.0
)

FetchContent_MakeAvailable(catch2)

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(lib)

target_include_directories(soteria_cli
    PUBLIC
        ${INCLUDE_DIR}
)

target_include_directories(soteria_core
    PUBLIC
        ${INCLUDE_DIR}
)

target_include_directories(soteria_utils
    PUBLIC
        ${INCLUDE_DIR}
)

add_executable(soteria lib/main.cpp)

include_directories(${Boost_INCLUDE_DIRS})
include_directories(${INCLUDE_DIR})

target_link_libraries(soteria
    PRIVATE
        ${Boost_LIBRARIES}
        OpenSSL::Crypto
        OpenSSL::SSL
        soteria_cli
        soteria_core
        soteria_utils
)

target_include_directories(soteria
    PUBLIC
        "${PROJECT_BINARY_DIR}"
        ${INCLUDE_DIR}
)

# 
# Testing
#

file(GLOB TEST_SOURCES tests/core/*.cpp tests/utils/*.cpp)
add_executable(soteria_tests ${TEST_SOURCES} lib/cli/cli.cpp)

target_link_libraries(soteria_tests
    PRIVATE
        ${Boost_LIBRARIES}
        Catch2::Catch2WithMain
        OpenSSL::Crypto
        soteria_cli
        soteria_core
        soteria_utils
)

include(CTest)
include(Catch)
catch_discover_tests(soteria_tests)
