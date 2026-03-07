// test_cipher_context.cpp
#include <gtest/gtest.h>
#include "../src/crypto_core/CipherContext.hpp"
#include "../src/des/DESCipher.hpp"
#include <fstream>
#include <filesystem>
#include <thread>
#include <random>
#include "../src/des/des_tables.cpp"
#include "../src/bits/Pbox_permutation.hpp"

namespace fs = std::filesystem;
using namespace crypto;

// Вспомогательная функция для генерации случайного IV нужного размера
Bytes generate_random_iv(size_t size) {
    Bytes iv(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    
    for (auto& byte : iv) {
        byte = static_cast<Byte>(dist(gen));
    }
    return iv;
}

// Фикстура для тестов CipherContext
class CipherContextTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Создаем временные файлы для тестов
        test_input_file = "test_input.txt";
        test_output_file = "test_output.bin";
        test_decrypted_file = "test_decrypted.txt";
        
        // Стандартный тестовый ключ DES (8 байт с учетом четности)
        test_key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
        
        // Создаем DES и устанавливаем ключ
        auto des = std::make_unique<DESCipher>();
        des->setKey(test_key);
        m_des = std::move(des);
    }
    
    void TearDown() override {
        // Удаляем временные файлы
        if (fs::exists(test_input_file)) {
            fs::remove(test_input_file);
        }
        if (fs::exists(test_output_file)) {
            fs::remove(test_output_file);
        }
        if (fs::exists(test_decrypted_file)) {
            fs::remove(test_decrypted_file);
        }
    }
    
    void create_test_file(const std::string& filename, const std::string& content) {
        std::ofstream file(filename, std::ios::binary);
        file << content;
        file.close();
    }
    
    std::string read_test_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
    }
    
    std::string test_input_file;
    std::string test_output_file;
    std::string test_decrypted_file;
    Bytes test_key;
    std::unique_ptr<DESCipher> m_des;
};

TEST_F(CipherContextTest, DebugPermutation) {
    Bytes key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    
    
    // Проверяем PC1 перестановку
    auto pc1_result = bit_Pbox_permutation(key, PC1, BitOrder::BIG_END, BitCountingBase::ONE);
    
    std::cout << std::endl;
    
    // Проверяем, что результат не пустой
    ASSERT_FALSE(pc1_result.empty());
    
    // Проверяем split operations
    auto C = bit_Pbox_permutation(pc1_result, SPLIT_C, BitOrder::BIG_END, BitCountingBase::ONE);
    auto D = bit_Pbox_permutation(pc1_result, SPLIT_D, BitOrder::BIG_END, BitCountingBase::ONE);
    
}

TEST_F(CipherContextTest, DebugKeyExpansion) 
{
    Bytes key1 = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    Bytes key2 = {0x24, 0x45, 0x68, 0x8A, 0xAA, 0xCD, 0xE0, 0xF2};
    
    DESCipher::DESKeyExpansion keyExp;
    
    auto roundKeys1 = keyExp.generateRoundKeys(key1);
    auto roundKeys2 = keyExp.generateRoundKeys(key2);
    
    // Проверьте, что round keys действительно разные
    for (int i = 0; i < 16; i++) {
        EXPECT_NE(roundKeys1[i], roundKeys2[i]);
    }
}

// Тесты конструктора
TEST_F(CipherContextTest, Constructor_ECB_WithoutIV) {
    EXPECT_NO_THROW({
        CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    });
}

TEST_F(CipherContextTest, Constructor_CBC_WithRandomIV) {
    auto iv = generate_random_iv(8);  // DES block size = 8
    EXPECT_NO_THROW({
        CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    });
}

TEST_F(CipherContextTest, Constructor_PCBC_WithRandomIV) {
    auto iv = generate_random_iv(8);
    EXPECT_NO_THROW({
        CipherContext context(std::move(m_des), PCBC_md, Zeros, iv);
    });
}

TEST_F(CipherContextTest, Constructor_NullCipher_Throws) {
    EXPECT_THROW({
        CipherContext context(nullptr, ECB_md, Zeros, {});
    }, std::invalid_argument);
}


// Тесты шифрования/дешифрования
TEST_F(CipherContextTest, EncryptDecrypt_ECB_Zeros) {
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    Bytes plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    Bytes ciphertext;
    Bytes decrypted;
    
    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CipherContextTest, EncryptDecrypt_CBC_ANSIX923) {
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    
    Bytes plaintext = {'T', 'e', 's', 't', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};
    Bytes ciphertext;
    Bytes decrypted;
    
    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);
    
    EXPECT_EQ(plaintext, decrypted);
}

// Тест 1: Разные размеры данных (короткие)
TEST_F(CipherContextTest, CBC_ANSIX923_VariousShortInputs) {
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    
    std::vector<std::string> inputs = {
        "A",                    // 1 байт
        "AB",                   // 2 байта
        "ABC",                  // 3 байта
        "ABCD",                 // 4 байта
        "ABCDE",                // 5 байт
        "ABCDEF",               // 6 байт
        "ABCDEFG",              // 7 байт
        "ABCDEFGH",             // 8 байт (ровно блок)
        "ABCDEFGHI"             // 9 байт
    };
    
    for (const auto& input : inputs) {
        Bytes plaintext(input.begin(), input.end());
        Bytes ciphertext;
        Bytes decrypted;
        
        context.encrypt(plaintext, ciphertext);
        context.decrypt(ciphertext, decrypted);
        
        EXPECT_EQ(plaintext, decrypted) << "Failed for input: " << input;
    }
}

// Тест 2: Граничные значения - пустая строка и 1 блок
TEST_F(CipherContextTest, CBC_ANSIX923_Boundaries) {
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    
    // Пустые данные
    Bytes empty;
    Bytes ciphertext1;
    Bytes decrypted1;
    context.encrypt(empty, ciphertext1);
    context.decrypt(ciphertext1, decrypted1);
    EXPECT_TRUE(decrypted1.empty());
    
    // Ровно 1 блок (8 байт)
    Bytes one_block = {'1', '2', '3', '4', '5', '6', '7', '8'};
    Bytes ciphertext2;
    Bytes decrypted2;
    context.encrypt(one_block, ciphertext2);
    context.decrypt(ciphertext2, decrypted2);
    EXPECT_EQ(one_block, decrypted2);
    
    // Ровно 2 блока (16 байт)
    Bytes two_blocks = {'1', '2', '3', '4', '5', '6', '7', '8', 
                        '9', '0', 'A', 'B', 'C', 'D', 'E', 'F'};
    Bytes ciphertext3;
    Bytes decrypted3;
    context.encrypt(two_blocks, ciphertext3);
    context.decrypt(ciphertext3, decrypted3);
    EXPECT_EQ(two_blocks, decrypted3);
}

// Тест 3: Специальные символы и бинарные данные
TEST_F(CipherContextTest, CBC_ANSIX923_BinaryData) {
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    
    // Данные с нулями в середине
    Bytes with_zeros = {'H', 'e', 0x00, 'l', 0x00, 'o', 0x00, 0x00, '!'};
    Bytes ciphertext1;
    Bytes decrypted1;
    context.encrypt(with_zeros, ciphertext1);
    context.decrypt(ciphertext1, decrypted1);
    EXPECT_EQ(with_zeros, decrypted1);
    
    // Все возможные байты от 0 до 255 (но не более 16, чтобы тест не был огромным)
    Bytes all_bytes;
    for (int i = 0; i < 16; i++) {
        all_bytes.push_back(static_cast<Byte>(i));
    }
    Bytes ciphertext2;
    Bytes decrypted2;
    context.encrypt(all_bytes, ciphertext2);
    context.decrypt(ciphertext2, decrypted2);
    EXPECT_EQ(all_bytes, decrypted2);
}

// Тест 4: Очень длинные данные (много блоков)
TEST_F(CipherContextTest, CBC_ANSIX923_LongData) {
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    
    // 1000 байт данных
    Bytes long_data;
    for (int i = 0; i < 1000; i++) {
        long_data.push_back(static_cast<Byte>(i % 256));
    }
    
    Bytes ciphertext;
    Bytes decrypted;
    
    context.encrypt(long_data, ciphertext);
    context.decrypt(ciphertext, decrypted);
    
    EXPECT_EQ(long_data.size(), decrypted.size());
    EXPECT_EQ(long_data, decrypted);
    
    // Проверяем размер ciphertext (должен быть кратен блоку)
    EXPECT_EQ(ciphertext.size() % 8, 0);
}

// Тест 5: Многопоточность с разными размерами
TEST_F(CipherContextTest, CBC_ANSIX923_Multithreaded) {
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    
    std::vector<size_t> thread_counts = {1, 2, 4, 8};
    std::vector<size_t> data_sizes = {1, 8, 15, 16, 17, 100, 101, 1000};
    
    for (size_t threads : thread_counts) {
        for (size_t size : data_sizes) {
            Bytes plaintext;
            for (size_t i = 0; i < size; i++) {
                plaintext.push_back(static_cast<Byte>(i % 256));
            }
            
            Bytes ciphertext;
            Bytes decrypted;
            
            context.encrypt(plaintext, ciphertext, threads);
            context.decrypt(ciphertext, decrypted, threads);
            
            EXPECT_EQ(plaintext, decrypted) 
                << "Failed for size=" << size << " threads=" << threads;
        }
    }
}

TEST_F(CipherContextTest, EncryptDecrypt_PCBC_Zeros) {
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), PCBC_md, Zeros, iv);
    
    Bytes plaintext = {'P', 'C', 'B', 'C', ' ', 't', 'e', 's', 't'};
    Bytes ciphertext;
    Bytes decrypted;
    
    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CipherContextTest, EncryptDecrypt_EmptyData) {
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    Bytes plaintext;
    Bytes ciphertext;
    Bytes decrypted;
    
    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);
    
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(CipherContextTest, EncryptDecrypt_ExactBlockSize) {
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    // Ровно 1 блок (8 байт)
    Bytes plaintext = {'1', '2', '3', '4', '5', '6', '7', '8'};
    Bytes ciphertext;
    Bytes decrypted;
    
    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CipherContextTest, EncryptDecrypt_MultipleThreads) {
    CipherContext context(std::move(m_des), ECB_md, ANSIX923, {});
    
    Bytes plaintext(1024, 'A');
    Bytes ciphertext;
    Bytes decrypted;
    
    context.encrypt(plaintext, ciphertext, 4);
    context.decrypt(ciphertext, decrypted, 4);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CipherContextTest, DifferentKeys_DifferentResults) 
{
    Bytes key1 = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    Bytes key2 = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    
    auto des1 = std::make_unique<DESCipher>();
    des1->setKey(key1);
    auto des2 = std::make_unique<DESCipher>();
    des2->setKey(key2);
    
    CipherContext context1(std::move(des1), ECB_md, Zeros, {});
    CipherContext context2(std::move(des2), ECB_md, Zeros, {});
    
    Bytes plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    Bytes ciphertext1, ciphertext2;
    
    context1.encrypt(plaintext, ciphertext1);
    context2.encrypt(plaintext, ciphertext2);
    
    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(CipherContextTest, EncryptDecrypt_File_ECB) {
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    std::string test_content = "Hello, World! This is a test file for ECB mode.";
    create_test_file(test_input_file, test_content);
    
    context.process_file(test_input_file, test_output_file, 2, true);
    context.process_file(test_output_file, test_decrypted_file, 2, false);
    
    std::string decrypted_content = read_test_file(test_decrypted_file);
    EXPECT_EQ(test_content, decrypted_content);
}

TEST_F(CipherContextTest, EncryptDecrypt_File_CBC) {
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    
    std::string test_content = "CBC mode file test with ANSI X.923 padding.";
    create_test_file(test_input_file, test_content);
    
    context.process_file(test_input_file, test_output_file, 1, true);
    context.process_file(test_output_file, test_decrypted_file, 1, false);
    
    std::string decrypted_content = read_test_file(test_decrypted_file);
    EXPECT_EQ(test_content, decrypted_content);
}

TEST_F(CipherContextTest, EncryptDecrypt_File_Async) 
{
    auto iv = generate_random_iv(8);
    CipherContext context(std::move(m_des), CBC_md, ANSIX923, iv);
    
    std::string test_content = "Async file processing test.";
    create_test_file(test_input_file, test_content);
    
    auto encrypt_future = context.encrypt_file(test_input_file, test_output_file, 2);
    encrypt_future.get();
    
    auto decrypt_future = context.decrypt_file(test_output_file, test_decrypted_file, 2);
    decrypt_future.get();
    
    std::string decrypted_content = read_test_file(test_decrypted_file);
    EXPECT_EQ(test_content, decrypted_content);
}

// Тесты ошибок
TEST_F(CipherContextTest, ProcessFile_InputNotFound) 
{
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    EXPECT_THROW({
        context.process_file("nonexistent_file.txt", test_output_file, 1, true);
    }, std::runtime_error);
}

TEST_F(CipherContextTest, Decrypt_InvalidData) 
{
    // Создаем контекст с DES, режим ECB, padding Zeros
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    // Создаем тестовый файл с данными, размер которых НЕ кратен 8
    const std::string test_input = "This data size is not multiple of 8";
    {
        std::ofstream file(test_input_file, std::ios::binary);
        file << test_input;
    }
    
    // Шифруем файл (padding должен добавиться автоматически)
    context.encrypt_file(test_input_file, test_output_file, 1);
    
    // Проверяем, что зашифрованный файл имеет размер, кратный 8
    std::ifstream encrypted(test_output_file, std::ios::binary | std::ios::ate);
    size_t encrypted_size = encrypted.tellg();
    encrypted.close();
    
    EXPECT_EQ(encrypted_size % 8, 0) << "Encrypted file size must be multiple of 8";
    
    // Дешифруем обратно
    std::string decrypted_file = "decrypted.txt";
    context.decrypt_file(test_output_file, decrypted_file, 1);
    
    // Проверяем, что расшифрованные данные совпадают с исходными
    std::ifstream decrypted(decrypted_file, std::ios::binary);
    std::string decrypted_data((std::istreambuf_iterator<char>(decrypted)),
                                std::istreambuf_iterator<char>());
    decrypted.close();
    
    EXPECT_EQ(decrypted_data, test_input) 
        << "Decrypted data should match original input";
    
    // Очистка
    std::remove(test_input_file.c_str());
    std::remove(test_output_file.c_str());
    std::remove(decrypted_file.c_str());
}

TEST_F(CipherContextTest, ConfigureCipherMode_Invalid) 
{
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    EXPECT_THROW({
        context.configure_cipher_mode(static_cast<CipherMd>(999));
    }, std::invalid_argument);
}

TEST_F(CipherContextTest, ConfigurePadding) 
{
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    EXPECT_NO_THROW({
        context.configure_padding(ANSIX923);
    });
    
    Bytes plaintext = {'T', 'e', 's', 't'};
    Bytes ciphertext;
    Bytes decrypted;
    
    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CipherContextTest, ConfigurePadding_Invalid) 
{
    CipherContext context(std::move(m_des), ECB_md, Zeros, {});
    
    EXPECT_THROW({
        context.configure_padding(static_cast<PaddingMode>(999));
    }, std::invalid_argument);
}

TEST_F(CipherContextTest, AllModeCombinations) 
{
    std::vector<CipherMd> modes = {ECB_md, CBC_md, PCBC_md};
    std::vector<PaddingMode> paddings = {Zeros, ANSIX923};
    
    for (auto mode : modes) {
        for (auto padding : paddings) {
            auto des = std::make_unique<DESCipher>();
            des->setKey(test_key);
            
            Bytes iv;
            if (mode != ECB_md) {
                iv = generate_random_iv(8);
            }
            
            CipherContext context(std::move(des), mode, padding, iv);
            
            Bytes plaintext = {'T', 'e', 's', 't', ' ', 'd', 'a', 't', 'a'};
            Bytes ciphertext;
            Bytes decrypted;
            
            context.encrypt(plaintext, ciphertext);
            context.decrypt(ciphertext, decrypted);
            
            EXPECT_EQ(plaintext, decrypted) 
                << "Failed for mode=" << static_cast<int>(mode) 
                << " padding=" << static_cast<int>(padding);
        }
    }
}
