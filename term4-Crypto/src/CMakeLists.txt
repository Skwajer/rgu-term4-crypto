add_library(crypto_lib STATIC
    bits/Pbox_permutation.cpp
    bits/Sbox_substitution.cpp
    bits/utils.cpp
)

target_include_directories(crypto_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})