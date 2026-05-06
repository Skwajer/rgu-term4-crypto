#include <fstream>
#include <gtest/gtest.h>
#include "../src/twofish/TwoFishCipher.hpp"
#include "../src/crypto_core/CipherContext.hpp"
#include <memory>
#include <iostream>
#include <string>

namespace crypto
{    
    class TwofishCipherTest : public ::testing::Test 
    {
    protected:
        void SetUp() override 
        {
            auto twofish = std::make_unique<TwofishCipher>();
            m_twofish = std::move(twofish);
        }
        
        Bytes generateRandomData(size_t size) 
        {
            Bytes data(size);
            for (size_t i = 0; i < size; i++) {
                data[i] = static_cast<Byte>(i * 0x33 + 0x5A);
            }
            return data;
        }

        std::unique_ptr<TwofishCipher> m_twofish;
    };

    TEST_F(TwofishCipherTest, SimpleRoundtrip) 
    {
        Bytes key(16, 0);
        Bytes plain(16, 0);
        plain[0] = 0x01;
        plain[1] = 0x23;
        plain[2] = 0x45;
        plain[3] = 0x67;
        plain[4] = 0x89;
        plain[5] = 0xAB;
        plain[6] = 0xCD;
        plain[7] = 0xEF;
        
        m_twofish->setKey(key);
        Bytes enc = m_twofish->encryptBlock(plain);
        Bytes dec = m_twofish->decryptBlock(enc);
        
        EXPECT_EQ(plain, dec);
    }

    TEST_F(TwofishCipherTest, ECB_Mode_10MB_bytes_array)
    {
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        m_twofish->setKey(key);
        CipherContext context(
            std::move(m_twofish), ECB_md, Zeros, {});
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

    TEST_F(TwofishCipherTest, ECB_Mode_300MB_bytes_array)
    {
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        m_twofish->setKey(key);
        CipherContext context(
            std::move(m_twofish), ECB_md, Zeros, {});
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

    TEST_F(TwofishCipherTest, file_test)
    {
        Bytes key = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
        };
        m_twofish->setKey(key);
        CipherContext context(
            std::move(m_twofish), ECB_md, Zeros, {});

        std::string in = "input.txt";
        std::string encrypted = "output.txt";
        std::string decrypted = "decrypted.txt";
        context.encrypt_file(in, encrypted);
        context.decrypt_file(encrypted, decrypted);
    }
}