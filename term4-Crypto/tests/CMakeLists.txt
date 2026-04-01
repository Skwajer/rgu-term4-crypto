cmake_minimum_required(VERSION 4.2)

add_executable(test_crypto_bits_permute
    test_pbox_permutation.cpp
)

target_link_libraries(test_crypto_bits_permute
    PRIVATE crypto_lib
    gtest
    gtest_main
)

add_executable(test_crypto_bits_sbox
    test_sbox_substitution.cpp
)

target_link_libraries(test_crypto_bits_sbox
    PRIVATE crypto_lib
    gtest
    gtest_main
)

add_executable(test_padding
    test_padding.cpp)

target_link_libraries(test_padding
    PRIVATE crypto_lib
    gtest
    gtest_main
)

add_executable(test_CipherContext
    test_CipherContext.cpp)

target_link_libraries(test_CipherContext
    PRIVATE crypto_lib
    gtest
    gtest_main
)

add_executable(test_CipherContextlab4
    test_CipherContext.cpp)

target_link_libraries(test_CipherContextlab4
    PRIVATE crypto_lib
    gtest
    gtest_main
)

add_executable(test_FermatPrimality
    test_Fermat_primality.cpp
    ../math/NumberTheoryService.cpp
    ../math/fermat_primality_test/FermatPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp)

target_link_libraries(test_FermatPrimality
    gtest
    gtest_main
)

add_executable(test_SolovayStrassenPrimality
    test_Solovay_Strassen_primality_test.cpp
    ../math/NumberTheoryService.cpp
    ../math/Solovay_Strassen_primality_test/SolovayStrassenPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp)

target_link_libraries(test_SolovayStrassenPrimality
    gtest
    gtest_main
)

add_executable(test_MillerRabinPrimality
    test_Miller_Rabin_primality_test.cpp
    ../math/NumberTheoryService.cpp
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp)

target_link_libraries(test_MillerRabinPrimality
    gtest
    gtest_main
)

add_executable(test_RSA
    test_RSA.cpp
    ../src/crypto_core/rsa/RSA.cpp
    ../src/crypto_core/rsa/RsaKeyGeneration.cpp
    ../math/NumberTheoryService.cpp
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp)

target_link_libraries(test_RSA
    gtest
    gtest_main
)

add_executable(test_FermatAttack
    test_FermatAttack.cpp
    ../src/cryptanalysis/VulnerableRsaKeyGenerator.cpp
    ../math/NumberTheoryService.cpp
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp
    )

target_link_libraries(test_FermatAttack
    gtest
    gtest_main
)

add_test(NAME test_FermatAttack COMMAND test_FermatAttack)
add_test(NAME test_RSA COMMAND test_RSA)
add_test(NAME test_MillerRabinPrimality COMMAND test_MillerRabinPrimality)
add_test(NAME test_SolovayStrassenPrimality COMMAND test_SolovayStrassenPrimality)
add_test(NAME test_FermatPrimality COMMAND test_FermatPrimality)
add_test(NAME test_crypto_bits_permute COMMAND test_crypto_bits_permute)
add_test(NAME test_crypto_bits_substitute COMMAND test_crypto_bits_substitute)
add_test(NAME test_crypto_paddings COMMAND test_padding)
add_test(NAME test_CipherContext COMMAND test_CipherContext)
add_test(NAME test_CipherContextlab4 COMMAND test_CipherContextlab4)


