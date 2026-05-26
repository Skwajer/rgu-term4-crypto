// test_3des_cipher_context.cpp
#include <gtest/gtest.h>

#include "../src/crypto_core/CipherContext.hpp"
#include "../src/des/3DES.hpp"

#include <filesystem>
#include <fstream>
#include <random>

namespace fs = std::filesystem;
using namespace crypto;

Bytes generate_random_iv(size_t size)
{
    Bytes iv(size);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    for (auto& byte : iv)
    {
        byte = static_cast<Byte>(dist(gen));
    }

    return iv;
}

class TripleDESCipherContextTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        test_input_file = "3des_input.txt";
        test_output_file = "3des_output.bin";
        test_decrypted_file = "3des_decrypted.txt";

        key_ede2 = {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,

            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10
        };

        key_ede3 = {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,

            0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,

            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1
        };
    }

    void TearDown() override
    {
        if (fs::exists(test_input_file))
            fs::remove(test_input_file);

        if (fs::exists(test_output_file))
            fs::remove(test_output_file);

        if (fs::exists(test_decrypted_file))
            fs::remove(test_decrypted_file);
    }

    void create_test_file(
        const std::string& filename,
        const std::string& content
    )
    {
        std::ofstream file(filename, std::ios::binary);

        file << content;
    }

    std::string read_test_file(const std::string& filename)
    {
        std::ifstream file(filename, std::ios::binary);

        return std::string(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
    }

protected:
    Bytes key_ede2;
    Bytes key_ede3;

    std::string test_input_file;
    std::string test_output_file;
    std::string test_decrypted_file;
};

TEST_F(TripleDESCipherContextTest, EncryptDecrypt_ECB_EDE2)
{
    auto tdes = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EDE2
    );

    tdes->setKey(key_ede2);

    CipherContext context(
        std::move(tdes),
        ECB_md,
        ANSIX923,
        {}
    );

    Bytes plaintext = {
        'H','e','l','l','o',
        ' ','3','D','E','S'
    };

    Bytes ciphertext;
    Bytes decrypted;

    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);

    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(TripleDESCipherContextTest, EncryptDecrypt_CBC_EDE3)
{
    auto tdes = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EDE3
    );

    tdes->setKey(key_ede3);

    CipherContext context(
        std::move(tdes),
        CBC_md,
        PKCS7,
        generate_random_iv(8)
    );

    Bytes plaintext = {
        'T','r','i','p','l','e',
        'D','E','S',' ','T','e',
        's','t'
    };

    Bytes ciphertext;
    Bytes decrypted;

    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);

    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(TripleDESCipherContextTest, DifferentKeys_DifferentCiphertext)
{
    Bytes modified_key = key_ede3;
    modified_key[0] ^= 0xFF;

    auto tdes1 = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EDE3
    );

    auto tdes2 = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EDE3
    );

    tdes1->setKey(key_ede3);
    tdes2->setKey(modified_key);

    CipherContext context1(
        std::move(tdes1),
        ECB_md,
        Zeros,
        {}
    );

    CipherContext context2(
        std::move(tdes2),
        ECB_md,
        Zeros,
        {}
    );

    Bytes plaintext = {
        '1','2','3','4',
        '5','6','7','8'
    };

    Bytes ciphertext1;
    Bytes ciphertext2;

    context1.encrypt(plaintext, ciphertext1);
    context2.encrypt(plaintext, ciphertext2);

    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(TripleDESCipherContextTest, EncryptDecrypt_LongData_Multithreaded)
{
    auto tdes = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EEE3
    );

    tdes->setKey(key_ede3);

    CipherContext context(
        std::move(tdes),
        crypto::ECB_md,
        crypto::Zeros,
        generate_random_iv(8)
    );

    Bytes plaintext;

    for (int i = 0; i < 10000; i++)
    {
        plaintext.push_back(
            static_cast<Byte>(i % 256)
        );
    }

    Bytes ciphertext;
    Bytes decrypted;

    context.encrypt(plaintext, ciphertext, 8);
    context.decrypt(ciphertext, decrypted, 8);

    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(TripleDESCipherContextTest, EncryptDecrypt_EmptyData)
{
    auto tdes = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EDE2
    );

    tdes->setKey(key_ede2);

    CipherContext context(
        std::move(tdes),
        ECB_md,
        ANSIX923,
        {}
    );

    Bytes plaintext;
    Bytes ciphertext;
    Bytes decrypted;

    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);

    EXPECT_TRUE(decrypted.empty());
}

TEST_F(TripleDESCipherContextTest, InvalidKeySize_Throws)
{
    auto tdes = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EDE3
    );

    Bytes invalid_key = {1, 2, 3};

    EXPECT_THROW({
        tdes->setKey(invalid_key);
    }, std::runtime_error);
}

TEST_F(TripleDESCipherContextTest, EncryptDecrypt_File_CBC)
{
    auto tdes = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EDE3
    );

    tdes->setKey(key_ede3);

    CipherContext context(
        std::move(tdes),
        CBC_md,
        crypto::Zeros,
        generate_random_iv(8)
    );

    std::string test_input_file =
        "/home/skwajer/dev/rgu-term4-crypto/term4-Crypto/tests/test_twofish.cpp";
    auto plaintext =
        read_test_file(test_input_file);


    context.process_file(
        test_input_file,
        test_output_file,
        4,
        true
    );

    context.process_file(
        test_output_file,
        test_decrypted_file,
        4,
        false
    );

    auto decrypted =
        read_test_file(test_decrypted_file);

    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(TripleDESCipherContextTest, SameKeysEquivalentToDES)
{
    Bytes single_key = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    };

    Bytes triple_key = single_key;

    triple_key.insert(
        triple_key.end(),
        single_key.begin(),
        single_key.end()
    );

    triple_key.insert(
        triple_key.end(),
        single_key.begin(),
        single_key.end()
    );

    auto tdes = std::make_unique<TripleDESCipher>(
        TripleDESCipher::EDE3
    );

    tdes->setKey(triple_key);

    CipherContext context(
        std::move(tdes),
        ECB_md,
        Zeros,
        {}
    );

    Bytes plaintext = {
        '1','2','3','4',
        '5','6','7','8'
    };

    Bytes ciphertext;
    Bytes decrypted;

    context.encrypt(plaintext, ciphertext);
    context.decrypt(ciphertext, decrypted);

    EXPECT_EQ(plaintext, decrypted);
}