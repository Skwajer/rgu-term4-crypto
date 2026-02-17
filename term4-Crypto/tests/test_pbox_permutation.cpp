#include "helpers.hpp"
#include <gtest/gtest.h>
#include "../src/bits/Pbox_permutation.hpp"

TEST(test_crypto_bits_permute, identity_zero_based_big_endian_multi_byte) {
  {
    auto bits = bits_from_string("10101100001101001110100100011101");
    auto expected = bits_from_string("10101100001101001110100100011101");
    std::vector<size_t> indexes(32);
    for (size_t i = 0; i < 32; i++) {
      indexes[i] = i;
    }
    EXPECT_EQ(expected,
              bit_Pbox_permutation(bits, indexes, BitOrder::BIG_END, BitCountingBase::ZERO));
  }
}