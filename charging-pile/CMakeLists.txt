cmake_minimum_required(VERSION 3.16)
project(clpkc_charging_pile LANGUAGES CXX)

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

find_package(OpenSSL REQUIRED)

add_executable(charging_pile
    src/main.cpp
    src/crypto_utils.cpp
    src/net_client.cpp
    src/config.cpp
)

target_include_directories(charging_pile PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_link_libraries(charging_pile PRIVATE OpenSSL::SSL OpenSSL::Crypto)
