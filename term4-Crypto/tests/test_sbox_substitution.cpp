#include <gtest/gtest.h>
#include "../src/bits/Sbox_substitution.hpp"

TEST(SboxSubstitutionTest, BasicSubstitution) {
    std::vector<uint8_t> input = {0b10110101};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b101, 0b10},
        {0b011, 0b01}
    };
    
    auto result = substitute(input, s_block, 3, 2);
    
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0b10010000);
}

TEST(SboxSubstitutionTest, EmptyInput) {
    std::vector<uint8_t> input;
    std::unordered_map<uint8_t, uint8_t> s_block = {{0, 1}};
    auto result = substitute(input, s_block, 4, 4);
    EXPECT_TRUE(result.empty());
}

TEST(SboxSubstitutionTest, CrossByteBoundary) {
    std::vector<uint8_t> input = {0b10110011, 0b11001010};
    std::unordered_map<uint8_t, uint8_t> s_block;
    for (int i = 0; i < 16; i++) {
        s_block[i] = ~i & 0xF;
    }
    
    auto result = substitute(input, s_block, 4, 4);
    
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], 0x4C);
    EXPECT_EQ(result[1], 0x35);
}

TEST(SboxSubstitutionTest, DifferentSizes) {
    std::vector<uint8_t> input = {0b10101010};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b1010, 0b10}
    };
    
    auto result = substitute(input, s_block, 4, 2);
    
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0b10100000);
}

TEST(SboxSubstitutionTest, RemainingBits) {
    std::vector<uint8_t> input = {0b10110101, 0b10000000};
    std::unordered_map<uint8_t, uint8_t> s_block;
    for (int i = 0; i < 8; i++) {
        s_block[i] = i;
    }
    
    auto result = substitute(input, s_block, 3, 3);
    
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], 0b10110101);
    EXPECT_EQ(result[1], 0b10110101 >> 1);
}

TEST(SboxSubstitutionTest, InvalidBlockSize) {
    std::vector<uint8_t> input = {0x00};
    std::unordered_map<uint8_t, uint8_t> s_block = {{0, 0}};
    
    EXPECT_THROW(substitute(input, s_block, 9, 8), std::invalid_argument);
    EXPECT_THROW(substitute(input, s_block, 8, 9), std::invalid_argument);
}

TEST(SboxSubstitutionTest, ZeroBlockSize) {
    std::vector<uint8_t> input = {0xAB, 0xCD};
    std::unordered_map<uint8_t, uint8_t> s_block = {{0, 0}};
    
    auto result = substitute(input, s_block, 0, 8);
    EXPECT_EQ(result, input);
}

TEST(SboxSubstitutionTest, KeyNotFound) {
    std::vector<uint8_t> input = {0xFF};
    std::unordered_map<uint8_t, uint8_t> s_block = {{0x00, 0x00}};
    
    EXPECT_THROW(substitute(input, s_block, 4, 4), std::out_of_range);
}