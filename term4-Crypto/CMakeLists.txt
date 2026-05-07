cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0135 NEW)

project(term4-crypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_Declare(
    BoostHeaders
    URL https://github.com/boostorg/boost/releases/download/boost-1.84.0/boost-1.84.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(FETCHCONTENT_QUIET OFF)

message(STATUS "Downloading Google Test...")
FetchContent_MakeAvailable(googletest)

message(STATUS "Downloading Boost headers...")
FetchContent_GetProperties(BoostHeaders)
if(NOT BoostHeaders_POPULATED)
    FetchContent_Populate(BoostHeaders)
    
    set(BOOST_INCLUDE_DIR ${boostheaders_SOURCE_DIR})
    message(STATUS "Boost headers downloaded to: ${BOOST_INCLUDE_DIR}")
endif()

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
    math/NumberTheoryService.cpp
    math/fermat_primality_test/FermatPrimalityTest.cpp
    math/TemplateProbabilisticPrimalityTest.cpp
    math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    math/Solovay_Strassen_primality_test/SolovayStrassenPrimalityTest.cpp
    src/rsa/RSA.cpp
    src/cryptanalysis/VulnerableRsaKeyGenerator.cpp
    src/Rijndael/RijndaelCipher.cpp
    src/twofish/TwoFishCipher.cpp
    src/mars/MarsCipher.cpp
    src/Elgamal/ElGamalKeyGeneration.cpp
    src/Elgamal/ElGamalCipher.cpp
    src/RabinCryptoSystem/RabinCryptosystem.cpp
    src/DSA/DSA.cpp
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
    ${CMAKE_CURRENT_SOURCE_DIR}/math
    ${BOOST_INCLUDE_DIR}
)

target_compile_definitions(crypto_demo PRIVATE
    BOOST_ALL_NO_LIB
    BOOST_MP_STANDALONE
)

add_subdirectory(tests)