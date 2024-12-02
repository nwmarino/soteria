cmake_minimum_required(VERSION 3.20.0)
set(CMAKE_CXX_STANDARD 20)
project(soteria)

cmake_policy(SET CMP0167 NEW)
find_package(Boost REQUIRED COMPONENTS filesystem program_options iostreams)
find_package(OpenSSL REQUIRED)

add_subdirectory(lib)

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(soteria_cli
    PUBLIC
        ${INCLUDE_DIR}/cli
)

target_include_directories(soteria_core
    PUBLIC
        ${INCLUDE_DIR}/core
)

target_include_directories(soteria_utils
    PUBLIC
        ${INCLUDE_DIR}/utils
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
