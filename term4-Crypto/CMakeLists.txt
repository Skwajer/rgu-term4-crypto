cmake_minimum_required(VERSION 3.15)

project(term4-crypto LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

# connect Google Test
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_subdirectory(src)

set(SOURCES
    src/des/DESCipher.cpp
    src/des/des_tables.cpp

    src/crypto_core/FeistelCipher.cpp
    src/crypto_core/FeistelNetwork.cpp
    src/crypto_core/CipherContext.cpp

    src/bits/Pbox_permutation.cpp
    src/bits/Sbox_substitution.cpp

    src/padding/padding.cpp
    src/mode/modes.cpp

    main.cpp
)

add_executable(crypto_demo ${SOURCES})


target_include_directories(crypto_demo PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bits
    ${CMAKE_CURRENT_SOURCE_DIR}/src/padding
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mode
    ${CMAKE_CURRENT_SOURCE_DIR}/src/des
)

add_subdirectory(tests)