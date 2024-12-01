cmake_minimum_required(VERSION 3.20.0)
set(CMAKE_CXX_STANDARD 20)
project(soteria)

find_package(OpenSSL REQUIRED)

add_subdirectory(lib)

set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(soteria_cli
    PUBLIC
        ${INCLUDE_DIR}/cli
)

target_include_directories(soteria_encryption
    PUBLIC
        ${INCLUDE_DIR}/encryption
)

add_executable(soteria lib/main.cpp)

include_directories(${INCLUDE_DIR})

target_link_libraries(soteria
    PRIVATE
        OpenSSL::Crypto
        OpenSSL::SSL
        soteria_cli
        soteria_encryption
)
