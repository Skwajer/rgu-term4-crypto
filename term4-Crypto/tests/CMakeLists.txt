cmake_minimum_required(VERSION 4.2)

add_executable(test_crypto_bits_permute
    test_pbox_permutation.cpp
)

target_link_libraries(test_crypto_bits_permute
    PRIVATE crypto_lib
    gtest
    gtest_main
)

add_test(NAME test_crypto_bits_permute COMMAND test_crypto_bits_permute)
