#include <gtest/gtest.h>
#include "../src/Rijndael/RijndaelCipher.hpp"
#include "../src/mode/modes.hpp"
#include "../src/crypto_core/CipherContext.hpp"
#include <memory>
#include <vector>
#include <iostream>

namespace crypto
{    
    class RijndaelCipherTest : public ::testing::Test 
    {
    protected:
        void SetUp() override 
        {
            auto AES_Rijndael_128_192 = std::make_unique<RijndaelCipher>(0x11B, 128, 192);
            m_AES_Rijndael_128_192 = std::move(AES_Rijndael_128_192);
        }
        
        Bytes generateRandomData(size_t size) 
        {
            Bytes data(size);
            for (size_t i = 0; i < size; i++) {
                data[i] = static_cast<Byte>(i * 0x33 + 0x5A);
            }
            return data;
        }

        std::unique_ptr<RijndaelCipher> m_AES_Rijndael_128_192;
    };

    // Тест 2: AES-192 (блок 128 бит, ключ 192 бит)
    TEST_F(RijndaelCipherTest, AES192Consistency) 
    {
        std::cout << "\n=== AES-192 Test (128-bit block, 192-bit key) ===" << std::endl;
        
        RijndaelCipher cipher(0x11B, 128, 192);
        
        Bytes key = {
            0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
            0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
            0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
        };
        
        cipher.setKey(key);
        
        Bytes plaintext = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
        };
        
        Bytes ciphertext = cipher.encryptBlock(plaintext);
        Bytes decrypted = cipher.decryptBlock(ciphertext);
        
        EXPECT_EQ(plaintext, decrypted);
        std::cout << "  ✓ Encrypt/Decrypt consistency verified (16 bytes)" << std::endl;
    }

    // Тест 3: AES-256 (блок 128 бит, ключ 256 бит) с несколькими блоками
    TEST_F(RijndaelCipherTest, AES256MultipleBlocks) 
    {
        std::cout << "\n=== AES-256 Test (128-bit block, 256-bit key, 3 blocks) ===" << std::endl;
        
        RijndaelCipher cipher(0x11B, 128, 256);
        
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        
        cipher.setKey(key);
        
        // Тестируем 3 блока подряд
        std::vector<Bytes> plaintexts;
        std::vector<Bytes> ciphertexts;
        
        for (int block = 0; block < 3; block++) {
            Bytes plaintext(16);
            for (int i = 0; i < 16; i++) {
                plaintext[i] = static_cast<Byte>(block * 16 + i);
            }
            plaintexts.push_back(plaintext);
            
            Bytes ciphertext = cipher.encryptBlock(plaintext);
            ciphertexts.push_back(ciphertext);
            
            Bytes decrypted = cipher.decryptBlock(ciphertext);
            EXPECT_EQ(plaintext, decrypted);
        }
        
        std::cout << "  ✓ All 3 blocks encrypted/decrypted successfully" << std::endl;
        
        // Проверка что разные блоки дают разный ciphertext
        EXPECT_NE(ciphertexts[0], ciphertexts[1]);
        EXPECT_NE(ciphertexts[1], ciphertexts[2]);
        std::cout << "  ✓ Different blocks produce different ciphertexts" << std::endl;
    }

    TEST_F(RijndaelCipherTest, ECB_ModeConsistency) 
    {
        std::cout << "\n=== ECB Mode Test with Rijndael (128-bit key, 128-bit block) ===" << std::endl;
        
        // Создаем шифр
        RijndaelCipher cipher(0x11B, 128, 128);
        
        // Ключ
        Bytes key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        
        cipher.setKey(key);
        
        // Режим ECB
        ECB ecb;
        
        // Тестовые данные (32 байта = 2 блока)
        Bytes plaintext = {
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
            0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
        };
        
        Bytes ciphertext;
        Bytes decrypted;
        
        // Шифруем
        ecb.encrypt(cipher, plaintext, ciphertext, 1);
        
        // Дешифруем
        ecb.decrypt(cipher, ciphertext, decrypted, 1);
        
        // Проверяем
        EXPECT_EQ(plaintext, decrypted);
    }

    TEST_F(RijndaelCipherTest, ECB_Mode_AES192) 
    {
        std::cout << "\n=== ECB Mode Test: AES-192 (128-bit block, 192-bit key) ===" << std::endl;
        
        RijndaelCipher cipher(0x11B, 128, 192);
        
        // 192-битный ключ (24 байта)
        Bytes key = {
            0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
            0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
            0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
        };
        
        cipher.setKey(key);
        
        ECB ecb;
        
        // 3 блока данных (48 байт)
        Bytes plaintext;
        for (size_t i = 0; i < 48; i++) {
            plaintext.push_back(static_cast<Byte>(i * 0x11));
        }
        
        Bytes ciphertext;
        Bytes decrypted;
        
        ecb.encrypt(cipher, plaintext, ciphertext, 1);
        ecb.decrypt(cipher, ciphertext, decrypted, 1);
        
        EXPECT_EQ(plaintext, decrypted);
        std::cout << "  ✓ AES-192: 48 bytes (3 blocks) encrypted/decrypted successfully" << std::endl;
    }

    TEST_F(RijndaelCipherTest, ECB_Mode_AES256) 
    {
        std::cout << "\n=== ECB Mode Test: AES-256 (128-bit block, 256-bit key) ===" << std::endl;
        
        RijndaelCipher cipher(0x11B, 128, 256);
        
        // 256-битный ключ (32 байта)
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        
        cipher.setKey(key);
        
        ECB ecb;
        
        // 4 блока данных (64 байта)
        Bytes plaintext;
        for (size_t i = 0; i < 64; i++) {
            plaintext.push_back(static_cast<Byte>(i * 0x23));
        }
        
        Bytes ciphertext;
        Bytes decrypted;
        
        ecb.encrypt(cipher, plaintext, ciphertext, 1);
        ecb.decrypt(cipher, ciphertext, decrypted, 1);
        
        EXPECT_EQ(plaintext, decrypted);
        std::cout << "  ✓ AES-256: 64 bytes (4 blocks) encrypted/decrypted successfully" << std::endl;
    }

    TEST_F(RijndaelCipherTest, ECB_Mode_Rijndael256Block) 
    {
        std::cout << "\n=== ECB Mode Test: Rijndael (256-bit block, 128-bit key) ===" << std::endl;
        
        // Rijndael с блоком 256 бит, ключом 128 бит
        RijndaelCipher cipher(0x11B, 256, 128);
        
        Bytes key = {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };
        
        cipher.setKey(key);
        
        ECB ecb;
        
        // 2 блока по 32 байта (64 байта всего)
        Bytes plaintext;
        for (size_t i = 0; i < 64; i++) {
            plaintext.push_back(static_cast<Byte>(i * 0x47));
        }
        
        Bytes ciphertext;
        Bytes decrypted;
        
        ecb.encrypt(cipher, plaintext, ciphertext, 1);
        ecb.decrypt(cipher, ciphertext, decrypted, 1);
        
        EXPECT_EQ(plaintext, decrypted);
        std::cout << "  ✓ Rijndael (256-bit block): 64 bytes (2 blocks) encrypted/decrypted successfully" << std::endl;
        
        // Проверка размера блока
        EXPECT_EQ(cipher.block_size(), 32);
        std::cout << "  ✓ Block size: " << cipher.block_size() << " bytes (256 bits)" << std::endl;
    }

    TEST_F(RijndaelCipherTest, ECB_Mode_10MB_bytes_array)
    {
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        m_AES_Rijndael_128_192->setKey(key);
        CipherContext context(
            std::move(m_AES_Rijndael_128_192), ECB_md, Zeros, {});
        const size_t DATA_SIZE = 10 * 1024 * 1024; 
        Bytes plaintext;
        Bytes ciphertext;
        Bytes decrypted;
        plaintext.reserve(DATA_SIZE);
        
        for (size_t i = 0; i < DATA_SIZE; i++) 
        {
            plaintext.push_back(static_cast<Byte>((i * 0x9E3779B9) ^ (i >> 16)) & 0xFF);
        }
        context.encrypt(plaintext, ciphertext, 32);
        context.decrypt(ciphertext, decrypted, 32);
        EXPECT_EQ(plaintext, decrypted);
    }

    TEST_F(RijndaelCipherTest, ECB_Mode_300MB_bytes_array)
    {
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        m_AES_Rijndael_128_192->setKey(key);
        CipherContext context(
            std::move(m_AES_Rijndael_128_192), ECB_md, Zeros, {});
        const size_t DATA_SIZE = 300 * 1024 * 1024; 
        Bytes plaintext;
        Bytes ciphertext;
        Bytes decrypted;
        plaintext.reserve(DATA_SIZE);
        
        for (size_t i = 0; i < DATA_SIZE; i++) 
        {
            plaintext.push_back(static_cast<Byte>((i * 0x9E3779B9) ^ (i >> 16)) & 0xFF);
        }
        context.encrypt(plaintext, ciphertext, 32);
        context.decrypt(ciphertext, decrypted, 32);
        EXPECT_EQ(plaintext, decrypted);
    }
}