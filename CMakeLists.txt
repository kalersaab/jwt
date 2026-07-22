cmake_minimum_required(VERSION 3.15)
project(jwt)

set(CMAKE_CXX_STANDARD 20)

# Find OpenSSL (required for HMAC-SHA256 / RSA-SHA256)
find_package(OpenSSL REQUIRED)

add_executable(jwt main.cpp)

target_include_directories(jwt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(jwt PRIVATE OpenSSL::SSL OpenSSL::Crypto)
