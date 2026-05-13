cmake_minimum_required(VERSION 3.16)
project(charging_pile_demo CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(charging_pile_demo
  src/main.cpp
  src/crypto_utils.cpp
  src/json_line.cpp
)

target_include_directories(charging_pile_demo PRIVATE src)
target_link_libraries(charging_pile_demo PRIVATE OpenSSL::SSL OpenSSL::Crypto)
