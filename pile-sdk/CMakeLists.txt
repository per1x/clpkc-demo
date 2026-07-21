cmake_minimum_required(VERSION 3.16)
project(clpkc_pile_sdk LANGUAGES CXX VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

# macOS Homebrew 上 OpenSSL 需显式提示路径；Linux 一般能自动找到。
if(APPLE AND NOT OPENSSL_ROOT_DIR)
    execute_process(COMMAND brew --prefix openssl@3 OUTPUT_VARIABLE BREW_OPENSSL
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(BREW_OPENSSL)
        set(OPENSSL_ROOT_DIR ${BREW_OPENSSL})
    endif()
endif()

find_package(OpenSSL 3.0 REQUIRED)

# ---- SDK 静态库 ----
add_library(clpkc_sdk STATIC clpkc_sdk.cpp)
target_include_directories(clpkc_sdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(clpkc_sdk PUBLIC OpenSSL::Crypto)

# ---- KAT 自测 ----
add_executable(clpkc_selftest selftest.cpp)
target_link_libraries(clpkc_selftest PRIVATE clpkc_sdk)

# `make test` / `ctest` 跑 KAT 全量
enable_testing()
add_test(NAME kat COMMAND clpkc_selftest)

install(TARGETS clpkc_sdk ARCHIVE DESTINATION lib)
install(FILES clpkc_sdk.h DESTINATION include)
