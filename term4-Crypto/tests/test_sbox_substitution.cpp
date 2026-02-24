#include <gtest/gtest.h>
#include "../src/bits/Sbox_substitution.hpp"

TEST(SboxSubstitutionTest, EmptyInput) {
    std::vector<uint8_t> input;
    std::unordered_map<uint8_t, uint8_t> s_block = {{0, 1}};
    auto result = substitute(input, s_block, 4, 4);
    EXPECT_TRUE(result.empty());
}

TEST(SboxSubstitutionTest, ZeroBlockSize) {
    std::vector<uint8_t> input = {0xAB, 0xCD};
    std::unordered_map<uint8_t, uint8_t> s_block = {{0, 0}};
    auto result = substitute(input, s_block, 0, 8);
    EXPECT_EQ(result, input);
}

TEST(SboxSubstitutionTest, InvalidBlockSize) {
    std::vector<uint8_t> input = {0x00};
    std::unordered_map<uint8_t, uint8_t> s_block = {{0, 0}};
    EXPECT_THROW(substitute(input, s_block, 9, 8), std::invalid_argument);
    EXPECT_THROW(substitute(input, s_block, 8, 9), std::invalid_argument);
}

TEST(SboxSubstitutionTest, KeyNotFound) {
    std::vector<uint8_t> input = {0xFF};
    std::unordered_map<uint8_t, uint8_t> s_block = {{0x00, 0x00}};
    EXPECT_THROW(substitute(input, s_block, 4, 4), std::out_of_range);
}

TEST(SboxSubstitutionTest, BasicSubstitution2bit) {
    std::vector<uint8_t> input = {0b10110101};  // 10 11 01 01
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b10, 0b01},  // 10 -> 01
        {0b11, 0b10},  // 11 -> 10
        {0b01, 0b11}   // 01 -> 11
    };
    auto result = substitute(input, s_block, 2, 2);
    
    ASSERT_EQ(result.size(), 1);
    // 10->01, 11->10, 01->11, 01->11
    // 01 10 11 11 = 0b01101111
    EXPECT_EQ(result[0], 0b01101111);
}


TEST(SboxSubstitutionTest, BasicSubstitution) {
    std::vector<uint8_t> input = {0b10110101};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b101, 0b10},
        {0b011, 0b01}
    };
    auto result = substitute(input, s_block, 3, 2);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0b10100100);
}


TEST(SboxSubstitutionTest, Identity4bit) {
    std::vector<uint8_t> input = {0b11001100};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b1100, 0b1100},
        {0b1100, 0b1100}  
    };
    auto result = substitute(input, s_block, 4, 4);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0b11001100);
}

TEST(SboxSubstitutionTest, SimpleInvert) {
    std::vector<uint8_t> input = {0b11001100};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b1100, 0b0011},
        {0b1100, 0b0011}
    };
    auto result = substitute(input, s_block, 4, 4);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0b00110011);
}

TEST(SboxSubstitutionTest, SimpleIdentity) {
    std::vector<uint8_t> input = {0b00100100};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b001, 0b001},
        {0b000, 0b000},
        {0b100, 0b100}
    };
    auto result = substitute(input, s_block, 3, 3);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0b00100100);
}

TEST(SboxSubstitutionTest, CrossByteSimple2) {
    // 2 байта: 0b00111100 0b00111100
    std::vector<uint8_t> input = {0b00111100, 0b00111100};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b0011, 0b1001},
        {0b1100, 0b0110}
    };
    auto result = substitute(input, s_block, 4, 4);
    ASSERT_EQ(result.size(), 2);
    
    printf("\nresult[0] = 0x%02X = ", result[0]);
    for (int i = 7; i >= 0; i--) {
        printf("%d", (result[0] >> i) & 1);
    }
    printf("\n");
    
    printf("result[1] = 0x%02X = ", result[1]);
    for (int i = 7; i >= 0; i--) {
        printf("%d", (result[1] >> i) & 1);
    }
    printf("\n");
    
    // Вход: 00111100 00111100
    // Блоки: 0011, 1100, 0011, 1100
    // После замены: 1001, 0110, 1001, 0110
    // В байтах: 10010110 10010110 = 0x96 0x96
    EXPECT_EQ(result[0], 0x96);
    EXPECT_EQ(result[1], 0x96);
}

TEST(SboxSubstitutionTest, OneByteTwoBlocks) {
    std::vector<uint8_t> input = {0b11001100};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b1100, 0b1010},
        {0b1100, 0b1010}
    };
    auto result = substitute(input, s_block, 4, 4);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0b10101010);
}

TEST(SboxSubstitutionTest, TwoBytesFourBlocks) {
    std::vector<uint8_t> input = {0b11001100, 0b00110011};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b1100, 0b1010},
        {0b0011, 0b0101}
    };
    auto result = substitute(input, s_block, 4, 4);
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], 0b10101010);  // 0xAA
    EXPECT_EQ(result[1], 0b01010101);  // 0x55
}

TEST(SboxSubstitutionTest, ThreeBitsCrossByte) {
    std::vector<uint8_t> input = {0b11100011, 0b10001110};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b111, 0b001},
        {0b000, 0b110},
        {0b011, 0b100},
        {0b100, 0b011},
        {0b110, 0b101}
    };
    auto result = substitute(input, s_block, 3, 3);
    ASSERT_EQ(result.size(), 2);
    // После замены должно быть 001 110 001 110 001 110
    printf("\nresult[0] = 0x%02X = ", result[0]);
    for (int i = 7; i >= 0; i--) {
        printf("%d", (result[0] >> i) & 1);
    }
    printf("\n");
    
    printf("result[1] = 0x%02X = ", result[1]);
    for (int i = 7; i >= 0; i--) {
        printf("%d", (result[1] >> i) & 1);
    }
    printf("\n");
    EXPECT_EQ(result[0], 0b00111000);
    EXPECT_EQ(result[1], 0b11100010);
}

TEST(SboxSubstitutionTest, SingleBitBlocks) {
    std::vector<uint8_t> input = {0b10101010};
    std::unordered_map<uint8_t, uint8_t> s_block = {
        {0b1, 0b0},
        {0b0, 0b1}
    };
    auto result = substitute(input, s_block, 1, 1);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0b01010101);
}