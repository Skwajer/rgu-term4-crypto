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
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp)

target_link_libraries(test_FermatPrimality
    gtest
    gtest_main
)

add_executable(test_SolovayStrassenPrimality
    test_Solovay_Strassen_primality_test.cpp
    ../math/NumberTheoryService.cpp
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
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
    ../src/rsa/RSA.cpp
    ../src/rsa/RsaKeyGeneration.cpp
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

add_executable(test_Rijndael
    test_Rijndael.cpp
    ../src/Rijndael/RijndaelCipher.cpp
    ../src/mode/modes.cpp
    ../src/padding/padding.cpp
    ../src/crypto_core/CipherContext.cpp
    )

target_link_libraries(test_Rijndael
    gtest
    gtest_main
)

add_executable(test_twofish
    test_twofish.cpp
    ../src/twofish/TwoFishCipher.cpp
    ../src/mode/modes.cpp
    ../src/padding/padding.cpp
    ../src/crypto_core/CipherContext.cpp
    )

target_link_libraries(test_twofish
    gtest
    gtest_main
)

add_executable(test_mars
    test_mars.cpp
    ../src/mars/MarsCipher.cpp
    ../src/mode/modes.cpp
    ../src/padding/padding.cpp
    ../src/crypto_core/CipherContext.cpp
    )

target_link_libraries(test_mars
    gtest
    gtest_main
)

add_executable(test_Elgamal
    test_ElGamalKeyGeneration.cpp
    ../src/Elgamal/ElGamalKeyGeneration.cpp
    ../src/Elgamal/ElGamalCipher.cpp
    ../src/mode/modes.cpp
    ../src/padding/padding.cpp
    ../src/crypto_core/CipherContext.cpp
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp
    ../math/NumberTheoryService.cpp
    )

target_link_libraries(test_Elgamal
    gtest
    gtest_main
)

add_executable(test_RabinCryptosystem
    test_RabinCryptosystem.cpp
    ../src/RabinCryptoSystem/RabinCryptosystem.cpp
    ../src/mode/modes.cpp
    ../src/padding/padding.cpp
    ../src/crypto_core/CipherContext.cpp
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp
    ../math/NumberTheoryService.cpp
    )

target_link_libraries(test_RabinCryptosystem
    gtest
    gtest_main
)

add_executable(test_DSA
    test_DSA.cpp
    ../src/DSA/DSA.cpp
    ../src/mode/modes.cpp
    ../src/padding/padding.cpp
    ../src/crypto_core/CipherContext.cpp
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp
    ../math/NumberTheoryService.cpp
    )

target_link_libraries(test_DSA
    gtest
    gtest_main
)

add_executable(test_TDES
    test_TDES.cpp
    ../src/des/3DES.cpp
    ../src/des/DESCipher.cpp
    ../src/des/des_tables.cpp
    ../src/crypto_core/FeistelCipher.cpp
    ../src/crypto_core/FeistelNetwork.cpp
    ../src/bits/Pbox_permutation.cpp
    ../src/bits/Sbox_substitution.cpp
    ../src/bits/utils.cpp
    ../src/mode/modes.cpp
    ../src/padding/padding.cpp
    ../src/crypto_core/CipherContext.cpp
    )

target_link_libraries(test_TDES
    gtest
    gtest_main
)

add_executable(test_DH
    test_DH.cpp
    ../src/Diffie-Hellman/DH.cpp
    ../math/NumberTheoryService.cpp
    ../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.cpp
    ../math/TemplateProbabilisticPrimalityTest.cpp
    )

target_link_libraries(test_DH
    gtest
    gtest_main
)

add_test(NAME test_DH COMMAND test_DH)

add_test(NAME test_TDES COMMAND test_TDES)
add_test(NAME test_DSA COMMAND test_DSA)
add_test(NAME test_RabinCryptosystem COMMAND test_RabinCryptosystem)
add_test(NAME test_Elgamal COMMAND test_Elgamal)
add_test(NAME test_mars COMMAND test_mars)
add_test(NAME test_twofish COMMAND test_twofish)
add_test(NAME test_Rijndael COMMAND test_Rijndael)
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

