#include <gtest/gtest.h>
#include "../src/mars/MarsCipher.hpp"
#include "../src/crypto_core/CipherContext.hpp"
#include <memory>
#include <iostream>

namespace crypto
{    
    class MarsCipherTest : public ::testing::Test 
    {
    protected:
        void SetUp() override 
        {
            auto mars = std::make_unique<MarsCipher>();
            m_mars = std::move(mars);
        }
        
        Bytes generateRandomData(size_t size) 
        {
            Bytes data(size);
            for (size_t i = 0; i < size; i++) {
                data[i] = static_cast<Byte>(i * 0x33 + 0x5A);
            }
            return data;
        }

        std::unique_ptr<MarsCipher> m_mars;
    };

    TEST_F(MarsCipherTest, ECB_Mode_10MB_bytes_array)
    {
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        m_mars->setKey(key);
        CipherContext context(
            std::move(m_mars), ECB_md, Zeros, {});
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

    TEST_F(MarsCipherTest, ECB_Mode_300MB_bytes_array)
    {
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        std::cout << key.size() << std::endl;
        m_mars->setKey(key);
        CipherContext context(
            std::move(m_mars), ECB_md, Zeros, {});
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