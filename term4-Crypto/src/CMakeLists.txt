add_library(crypto_lib STATIC
    bits/Pbox_permutation.cpp
    bits/Sbox_substitution.cpp
    bits/utils.cpp
    padding/padding.cpp
    mode/modes.cpp
    des/DESCipher.cpp
    crypto_core/CipherContext.cpp
    crypto_core/FeistelCipher.cpp
    crypto_core/FeistelNetwork.cpp

)

target_include_directories(crypto_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})