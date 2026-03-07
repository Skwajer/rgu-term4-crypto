#include <gtest/gtest.h>
#include "../src/padding/padding.hpp"
#include <vector>
#include <cstdint>

using namespace crypto;
using Bytes = std::vector<uint8_t>;

// Тесты для ZerosPadding
class ZerosPaddingTest : public ::testing::Test {
protected:
    ZerosPadding padding;
};

TEST_F(ZerosPaddingTest, Apply_NoPaddingNeeded) {
    Bytes data = {0x01, 0x02, 0x03, 0x04};
    size_t block_size = 4;
    
    auto result = padding.apply(data, block_size);
    
    EXPECT_EQ(result, data);
    EXPECT_EQ(result.size(), 4);
}

TEST_F(ZerosPaddingTest, Apply_WithPadding) {
    Bytes data = {0x01, 0x02, 0x03};
    size_t block_size = 4;
    
    auto result = padding.apply(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03, 0x00};
    EXPECT_EQ(result, expected);
    EXPECT_EQ(result.size(), 4);
}

TEST_F(ZerosPaddingTest, Apply_MultipleBlocksWithPadding) {
    Bytes data = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t block_size = 4;
    
    auto result = padding.apply(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00};
    EXPECT_EQ(result, expected);
    EXPECT_EQ(result.size(), 8);
}

TEST_F(ZerosPaddingTest, Apply_EmptyData) {
    Bytes data = {};
    size_t block_size = 8;
    
    auto result = padding.apply(data, block_size);
    
    Bytes expected = {};
    EXPECT_EQ(result, expected);
    EXPECT_EQ(result.size(), 0);
}

TEST_F(ZerosPaddingTest, Apply_ZeroBlockSize) {
    Bytes data = {0x01, 0x02, 0x03};
    
    EXPECT_THROW(padding.apply(data, 0), std::invalid_argument);
}

TEST_F(ZerosPaddingTest, Remove_SimpleCase) {
    Bytes data = {0x01, 0x02, 0x03, 0x00};
    size_t block_size = 4;
    
    auto result = padding.remove(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03};
    EXPECT_EQ(result, expected);
}

TEST_F(ZerosPaddingTest, Remove_MultipleZeros) {
    Bytes data = {0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t block_size = 8;
    
    auto result = padding.remove(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03};
    EXPECT_EQ(result, expected);
}

TEST_F(ZerosPaddingTest, Remove_NoPadding) {
    Bytes data = {0x01, 0x02, 0x03, 0x04};
    size_t block_size = 4;
    
    auto result = padding.remove(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(result, expected);
}

TEST_F(ZerosPaddingTest, Remove_InvalidDataNotMultipleOfBlock) {
    Bytes data = {0x01, 0x02, 0x03};
    size_t block_size = 4;
    
    EXPECT_THROW(padding.remove(data, block_size), std::invalid_argument);
}

TEST_F(ZerosPaddingTest, Remove_EmptyData) {
    Bytes data = {};
    size_t block_size = 8;
    
    EXPECT_THROW(padding.remove(data, block_size), std::invalid_argument);
}

// Тесты для AnsiX923Padding
class AnsiX923PaddingTest : public ::testing::Test {
protected:
    AnsiX923Padding padding;
};

TEST_F(AnsiX923PaddingTest, Apply_NoPaddingNeeded) {
    Bytes data = {0x01, 0x02, 0x03, 0x04};
    size_t block_size = 4;
    
    auto result = padding.apply(data, block_size);
    
    EXPECT_EQ(result, data);
    EXPECT_EQ(result.size(), 4);
}

TEST_F(AnsiX923PaddingTest, Apply_WithPadding) {
    Bytes data = {0x01, 0x02, 0x03};
    size_t block_size = 4;
    
    auto result = padding.apply(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03, 0x01};
    EXPECT_EQ(result, expected);
    EXPECT_EQ(result.size(), 4);
}

TEST_F(AnsiX923PaddingTest, Apply_MultipleBlocksWithPadding) {
    Bytes data = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t block_size = 4;
    
    auto result = padding.apply(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x03};
    EXPECT_EQ(result, expected);
    EXPECT_EQ(result.size(), 8);
}

TEST_F(AnsiX923PaddingTest, Apply_LargePadding) {
    Bytes data = {0x01};
    size_t block_size = 8;
    
    auto result = padding.apply(data, block_size);
    
    // Ожидаем: данные + 6 нулей + значение 7 (количество добавленных байт)
    Bytes expected = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    EXPECT_EQ(result, expected);
    EXPECT_EQ(result.size(), 8);
}

TEST_F(AnsiX923PaddingTest, Apply_EmptyData) {
    Bytes data = {};
    size_t block_size = 8;
    
    auto result = padding.apply(data, block_size);
    
    Bytes expected = {};
    EXPECT_EQ(result, expected);
    EXPECT_EQ(result.size(), 0);
}

TEST_F(AnsiX923PaddingTest, Apply_ZeroBlockSize) {
    Bytes data = {0x01, 0x02, 0x03};
    
    EXPECT_THROW(padding.apply(data, 0), std::invalid_argument);
}

TEST_F(AnsiX923PaddingTest, Remove_SimpleCase) {
    Bytes data = {0x01, 0x02, 0x03, 0x01};
    size_t block_size = 4;
    
    auto result = padding.remove(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03, 0x01};
    EXPECT_EQ(result, expected);
}

TEST_F(AnsiX923PaddingTest, Remove_MultipleZeros) {
    Bytes data = {0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x05};
    size_t block_size = 8;
    
    auto result = padding.remove(data, block_size);
    
    Bytes expected = {0x01, 0x02, 0x03};
    EXPECT_EQ(result, expected);
}

TEST_F(AnsiX923PaddingTest, Remove_LargePadding) {
    Bytes data = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    size_t block_size = 8;
    
    auto result = padding.remove(data, block_size);
    
    Bytes expected = {0x01};
    EXPECT_EQ(result, expected);
}

TEST_F(AnsiX923PaddingTest, Remove_NoPadding) {
    Bytes data = {0x01, 0x02, 0x03, 0x04};
    size_t block_size = 4;
    
    EXPECT_THROW(padding.remove(data, block_size), std::invalid_argument);
}

TEST_F(AnsiX923PaddingTest, Remove_InvalidPadding) {
    // Неправильное заполнение: последний байт указывает на 2 байта паддинга,
    // но предпоследний байт не ноль
    Bytes data = {0x01, 0x02, 0x03, 0xFF, 0x02};
    size_t block_size = 4;
    
    EXPECT_THROW(padding.remove(data, block_size), std::invalid_argument);
}

TEST_F(AnsiX923PaddingTest, Remove_InvalidDataNotMultipleOfBlock) {
    Bytes data = {0x01, 0x02, 0x03};
    size_t block_size = 4;
    
    EXPECT_THROW(padding.remove(data, block_size), std::invalid_argument);
}

TEST_F(AnsiX923PaddingTest, Remove_EmptyData) {
    Bytes data = {};
    size_t block_size = 8;
    
    EXPECT_THROW(padding.remove(data, block_size), std::invalid_argument);
}

// Тесты для проверки совместимости apply и remove
TEST_F(AnsiX923PaddingTest, ApplyThenRemove) {
    Bytes original = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t block_size = 8;
    
    auto padded = padding.apply(original, block_size);
    auto unpadded = padding.remove(padded, block_size);
    
    EXPECT_EQ(unpadded, original);
}

TEST_F(ZerosPaddingTest, ApplyThenRemove) {
    Bytes original = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t block_size = 8;
    
    auto padded = padding.apply(original, block_size);
    auto unpadded = padding.remove(padded, block_size);
    
    EXPECT_EQ(unpadded, original);
}

// Граничные случаи
TEST_F(AnsiX923PaddingTest, Apply_BlockSizeOne) {
    Bytes data = {0x01};
    size_t block_size = 1;
    
    auto result = padding.apply(data, block_size);
    
    EXPECT_EQ(result, data);
    EXPECT_EQ(result.size(), 1);
}

TEST_F(AnsiX923PaddingTest, Remove_BlockSizeOne) {
    Bytes data = {0x01};
    size_t block_size = 1;
    
    auto result = padding.remove(data, block_size);
    
    EXPECT_EQ(result, data);
    EXPECT_EQ(result.size(), 1);
}

// Основная функция для запуска тестов
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}