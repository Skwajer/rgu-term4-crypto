// test_modes.cpp
#include <gtest/gtest.h>
#include <vector>
#include <algorithm>
#include <random>
#include "../src/crypto_core/ISymmetricCipher.hpp"
#include "../src/mode/modes.hpp"
#include "../src/des/DESCipher.hpp"

namespace crypto {
namespace testing {

using namespace crypto;

Bytes generate_random_data(size_t size) {
    Bytes data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    
    for (auto& byte : data) {
        byte = static_cast<Byte>(dist(gen));
    }
    return data;
}

bool are_bytes_equal(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin());
}

class ModeTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        test_key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
        
        auto des = std::make_unique<DESCipher>();
        des->setKey(test_key);
        cipher = std::move(des);
        
        bs = cipher->block_size();
    }
    
    std::unique_ptr<ISymmetricCipher> cipher;
    Bytes test_key;
    size_t bs;
};

// ==================== CFB Mode Tests ====================

class CFBModeTest : public ModeTestBase {};

TEST_F(CFBModeTest, Constructor_ValidIV) {
    Bytes iv = generate_random_data(bs);
    EXPECT_NO_THROW({
        CFB mode(iv);
    });
}

TEST_F(CFBModeTest, Constructor_EmptyIV_Accepts) {
    Bytes empty_iv;
    EXPECT_NO_THROW({
        CFB mode(empty_iv);
    });
}

TEST_F(CFBModeTest, Constructor_InvalidIVSize_Throws) {
    Bytes iv_too_small = generate_random_data(bs - 1);
    
    CFB mode(iv_too_small); 
    
    Bytes plaintext = generate_random_data(bs * 3);
    Bytes ciphertext;
    Bytes decrypted;
    
    EXPECT_THROW({
        mode.encrypt(*cipher, plaintext, ciphertext, 1);
    }, std::invalid_argument);
}

TEST_F(CFBModeTest, EncryptDecrypt_SingleBlock) {
    Bytes iv = generate_random_data(bs);
    CFB mode(iv);
    
    Bytes plaintext = generate_random_data(bs);
    Bytes ciphertext;
    Bytes decrypted;
    
    mode.encrypt(*cipher, plaintext, ciphertext, 1);
    mode.decrypt(*cipher, ciphertext, decrypted, 1);
    
    EXPECT_TRUE(are_bytes_equal(plaintext, decrypted));
}

TEST_F(CFBModeTest, EncryptDecrypt_MultipleBlocks) {
    Bytes iv = generate_random_data(bs);
    CFB mode(iv);
    
    std::vector<size_t> block_counts = {1, 2, 5, 10, 100};
    
    for (size_t num_blocks : block_counts) {
        Bytes plaintext = generate_random_data(bs * num_blocks);
        Bytes ciphertext;
        Bytes decrypted;
        
        mode.encrypt(*cipher, plaintext, ciphertext, 1);
        mode.decrypt(*cipher, ciphertext, decrypted, 1);
        
        EXPECT_TRUE(are_bytes_equal(plaintext, decrypted))
            << "Failed for " << num_blocks << " blocks";
    }
}

TEST_F(CFBModeTest, EncryptDecrypt_NonAlignedInput_Throws) {
    Bytes iv = generate_random_data(bs);
    CFB mode(iv);
    
    Bytes plaintext_not_aligned = generate_random_data(bs * 3 + 1);
    Bytes ciphertext;
    
    EXPECT_THROW({
        mode.encrypt(*cipher, plaintext_not_aligned, ciphertext, 1);
    }, std::invalid_argument);
}

TEST_F(CFBModeTest, DifferentIVs_DifferentCiphertext) {
    Bytes iv1 = generate_random_data(bs);
    Bytes iv2 = generate_random_data(bs);
    
    // Убедимся, что IV разные
    while (are_bytes_equal(iv1, iv2)) {
        iv2 = generate_random_data(bs);
    }
    
    CFB mode1(iv1);
    CFB mode2(iv2);
    
    Bytes plaintext = generate_random_data(bs * 4);
    Bytes ciphertext1, ciphertext2;
    
    mode1.encrypt(*cipher, plaintext, ciphertext1, 1);
    mode2.encrypt(*cipher, plaintext, ciphertext2, 1);
    
    EXPECT_FALSE(are_bytes_equal(ciphertext1, ciphertext2));
}

TEST_F(CFBModeTest, SameIV_SameCiphertext) {
    Bytes iv = generate_random_data(bs);
    
    CFB mode1(iv);
    CFB mode2(iv);
    
    Bytes plaintext = generate_random_data(bs * 4);
    Bytes ciphertext1, ciphertext2;
    
    mode1.encrypt(*cipher, plaintext, ciphertext1, 1);
    mode2.encrypt(*cipher, plaintext, ciphertext2, 1);
    
    EXPECT_TRUE(are_bytes_equal(ciphertext1, ciphertext2));
}

TEST_F(CFBModeTest, Decrypt_ManipulatedCiphertext_PropagatesError) {
    Bytes iv = generate_random_data(bs);
    CFB mode(iv);
    
    Bytes plaintext = generate_random_data(bs * 5);
    Bytes ciphertext;
    Bytes decrypted;
    
    mode.encrypt(*cipher, plaintext, ciphertext, 1);
    
    ciphertext[bs * 2 + 3] ^= 0xFF;
    
    mode.decrypt(*cipher, ciphertext, decrypted, 1);
    
    EXPECT_FALSE(are_bytes_equal(plaintext, decrypted));
}

// ==================== OFB Mode Tests ====================

class OFBModeTest : public ModeTestBase {};

TEST_F(OFBModeTest, Constructor_ValidIV) {
    Bytes iv = generate_random_data(bs);
    EXPECT_NO_THROW({
        OFB mode(iv);
    });
}

TEST_F(OFBModeTest, Constructor_EmptyIV_Accepts) {
    Bytes empty_iv;
    EXPECT_NO_THROW({
        OFB mode(empty_iv);
    });
}

TEST_F(OFBModeTest, Constructor_InvalidIVSize_Throws) {
    Bytes iv_too_small = generate_random_data(bs - 1);
    OFB mode(iv_too_small);
    
    Bytes plaintext = generate_random_data(bs * 3);
    Bytes ciphertext;
    
    EXPECT_THROW({
        mode.encrypt(*cipher, plaintext, ciphertext, 1);
    }, std::invalid_argument);
}

TEST_F(OFBModeTest, EncryptDecrypt_SingleBlock) {
    Bytes iv = generate_random_data(bs);
    OFB mode(iv);
    
    Bytes plaintext = generate_random_data(bs);
    Bytes ciphertext;
    Bytes decrypted;
    
    mode.encrypt(*cipher, plaintext, ciphertext, 1);
    mode.decrypt(*cipher, ciphertext, decrypted, 1);
    
    EXPECT_TRUE(are_bytes_equal(plaintext, decrypted));
}

TEST_F(OFBModeTest, EncryptDecrypt_MultipleBlocks) {
    Bytes iv = generate_random_data(bs);
    OFB mode(iv);
    
    std::vector<size_t> block_counts = {1, 2, 5, 10, 100};
    
    for (size_t num_blocks : block_counts) {
        Bytes plaintext = generate_random_data(bs * num_blocks);
        Bytes ciphertext;
        Bytes decrypted;
        
        mode.encrypt(*cipher, plaintext, ciphertext, 1);
        mode.decrypt(*cipher, ciphertext, decrypted, 1);
        
        EXPECT_TRUE(are_bytes_equal(plaintext, decrypted))
            << "Failed for " << num_blocks << " blocks";
    }
}

TEST_F(OFBModeTest, EncryptAndDecrypt_UseSameProcess) {
    Bytes iv = generate_random_data(bs);
    OFB mode(iv);
    
    Bytes data = generate_random_data(bs * 5);
    Bytes encrypted;
    Bytes decrypted;
    Bytes double_encrypted;
    
    mode.encrypt(*cipher, data, encrypted, 1);
    mode.decrypt(*cipher, encrypted, decrypted, 1);
    mode.encrypt(*cipher, encrypted, double_encrypted, 1);
    
    EXPECT_TRUE(are_bytes_equal(data, decrypted));
    EXPECT_TRUE(are_bytes_equal(data, double_encrypted));
}

TEST_F(OFBModeTest, DifferentIVs_DifferentCiphertext) {
    Bytes iv1 = generate_random_data(bs);
    Bytes iv2 = generate_random_data(bs);
    
    while (are_bytes_equal(iv1, iv2)) {
        iv2 = generate_random_data(bs);
    }
    
    OFB mode1(iv1);
    OFB mode2(iv2);
    
    Bytes plaintext = generate_random_data(bs * 4);
    Bytes ciphertext1, ciphertext2;
    
    mode1.encrypt(*cipher, plaintext, ciphertext1, 1);
    mode2.encrypt(*cipher, plaintext, ciphertext2, 1);
    
    EXPECT_FALSE(are_bytes_equal(ciphertext1, ciphertext2));
}

TEST_F(OFBModeTest, SameIV_SameCiphertext) {
    Bytes iv = generate_random_data(bs);
    
    OFB mode1(iv);
    OFB mode2(iv);
    
    Bytes plaintext = generate_random_data(bs * 4);
    Bytes ciphertext1, ciphertext2;
    
    mode1.encrypt(*cipher, plaintext, ciphertext1, 1);
    mode2.encrypt(*cipher, plaintext, ciphertext2, 1);
    
    EXPECT_TRUE(are_bytes_equal(ciphertext1, ciphertext2));
}

TEST_F(OFBModeTest, Decrypt_ManipulatedCiphertext_LocalError) {
    Bytes iv = generate_random_data(bs);
    OFB mode(iv);
    
    Bytes plaintext = generate_random_data(bs * 5);
    Bytes ciphertext;
    Bytes decrypted;
    
    mode.encrypt(*cipher, plaintext, ciphertext, 1);
    
    ciphertext[bs * 2 + 3] ^= 0xFF;
    
    mode.decrypt(*cipher, ciphertext, decrypted, 1);
    
    EXPECT_FALSE(are_bytes_equal(plaintext, decrypted));
}

// ==================== CTR Mode Tests ====================

class CTRModeTest : public ModeTestBase {};

TEST_F(CTRModeTest, Constructor_ValidNonce) {
    Bytes nonce = generate_random_data(4);
    EXPECT_NO_THROW({
        CTR mode(nonce);
    });
}

TEST_F(CTRModeTest, Constructor_EmptyNonce_Accepts) {
    Bytes empty_nonce;
    EXPECT_NO_THROW({
        CTR mode(empty_nonce);
    });
}

TEST_F(CTRModeTest, Constructor_InvalidNonceSize_Throws) {
    Bytes invalid_nonce = generate_random_data(5);
    
    CTR mode(invalid_nonce);
    
    Bytes plaintext = generate_random_data(bs * 3);
    Bytes ciphertext;
    
    EXPECT_THROW({
        mode.encrypt(*cipher, plaintext, ciphertext, 1);
    }, std::invalid_argument);
}

TEST_F(CTRModeTest, EncryptDecrypt_SingleBlock) {
    Bytes nonce = generate_random_data(4);
    CTR mode(nonce);
    
    Bytes plaintext = generate_random_data(bs);
    Bytes ciphertext;
    Bytes decrypted;
    
    mode.encrypt(*cipher, plaintext, ciphertext, 1);
    mode.decrypt(*cipher, ciphertext, decrypted, 1);
    
    EXPECT_TRUE(are_bytes_equal(plaintext, decrypted));
}

TEST_F(CTRModeTest, EncryptDecrypt_MultipleBlocks) {
    Bytes nonce = generate_random_data(4);
    CTR mode(nonce);
    
    std::vector<size_t> block_counts = {1, 2, 5, 10, 100};
    
    for (size_t num_blocks : block_counts) {
        Bytes plaintext = generate_random_data(bs * num_blocks);
        Bytes ciphertext;
        Bytes decrypted;
        
        mode.encrypt(*cipher, plaintext, ciphertext, 1);
        mode.decrypt(*cipher, ciphertext, decrypted, 1);
        
        EXPECT_TRUE(are_bytes_equal(plaintext, decrypted))
            << "Failed for " << num_blocks << " blocks";
    }
}

TEST_F(CTRModeTest, EncryptAndDecrypt_AreSame) {
    Bytes nonce = generate_random_data(4);
    CTR mode(nonce);
    
    Bytes data = generate_random_data(bs * 5);
    Bytes encrypted;
    Bytes decrypted;
    Bytes double_encrypted;
    
    mode.encrypt(*cipher, data, encrypted, 1);
    mode.decrypt(*cipher, encrypted, decrypted, 1);
    mode.encrypt(*cipher, encrypted, double_encrypted, 1);
    
    EXPECT_TRUE(are_bytes_equal(data, decrypted));
    EXPECT_TRUE(are_bytes_equal(data, double_encrypted));
}

TEST_F(CTRModeTest, Multithreaded_Encryption) {
    Bytes nonce = generate_random_data(4);
    CTR mode(nonce);
    
    std::vector<size_t> thread_counts = {1, 2, 4};
    std::vector<size_t> data_sizes = {bs * 10, bs * 100};
    
    for (size_t threads : thread_counts) {
        for (size_t size : data_sizes) {
            Bytes plaintext = generate_random_data(size);
            Bytes ciphertext;
            Bytes decrypted;
            
            mode.encrypt(*cipher, plaintext, ciphertext, threads);
            mode.decrypt(*cipher, ciphertext, decrypted, threads);
            
            EXPECT_TRUE(are_bytes_equal(plaintext, decrypted))
                << "Failed with threads=" << threads << ", size=" << size;
        }
    }
}

TEST_F(CTRModeTest, Multithreaded_CompareWithSingleThread) {
    Bytes nonce = generate_random_data(4);
    CTR mode(nonce);
    
    Bytes plaintext = generate_random_data(bs * 123);
    
    Bytes ciphertext_single;
    Bytes ciphertext_multi;
    
    mode.encrypt(*cipher, plaintext, ciphertext_single, 1);
    mode.encrypt(*cipher, plaintext, ciphertext_multi, 4);
    
    EXPECT_TRUE(are_bytes_equal(ciphertext_single, ciphertext_multi));
}

TEST_F(CTRModeTest, DifferentNonces_DifferentCiphertext) {
    Bytes nonce1 = generate_random_data(4);
    Bytes nonce2 = generate_random_data(4);
    
    while (are_bytes_equal(nonce1, nonce2)) {
        nonce2 = generate_random_data(4);
    }
    
    CTR mode1(nonce1);
    CTR mode2(nonce2);
    
    Bytes plaintext = generate_random_data(bs * 10);
    Bytes ciphertext1, ciphertext2;
    
    mode1.encrypt(*cipher, plaintext, ciphertext1, 1);
    mode2.encrypt(*cipher, plaintext, ciphertext2, 1);
    
    EXPECT_FALSE(are_bytes_equal(ciphertext1, ciphertext2));
}

TEST_F(CTRModeTest, SameNonce_SameCiphertext) {
    Bytes nonce = generate_random_data(4);
    
    CTR mode1(nonce);
    CTR mode2(nonce);
    
    Bytes plaintext = generate_random_data(bs * 10);
    Bytes ciphertext1, ciphertext2;
    
    mode1.encrypt(*cipher, plaintext, ciphertext1, 1);
    mode2.encrypt(*cipher, plaintext, ciphertext2, 1);
    
    EXPECT_TRUE(are_bytes_equal(ciphertext1, ciphertext2));
}

TEST_F(CTRModeTest, Decrypt_ManipulatedCiphertext_LocalError) {
    Bytes nonce = generate_random_data(4);
    CTR mode(nonce);
    
    Bytes plaintext = generate_random_data(bs * 5);
    Bytes ciphertext;
    Bytes decrypted;
    
    mode.encrypt(*cipher, plaintext, ciphertext, 1);
    
    ciphertext[bs * 2 + 3] ^= 0xFF;
    
    mode.decrypt(*cipher, ciphertext, decrypted, 1);
    
    EXPECT_FALSE(are_bytes_equal(plaintext, decrypted));
}

// ==================== Random Delta Mode Tests ====================

class RandomDeltaModeTest : public ModeTestBase {};

TEST_F(RandomDeltaModeTest, Constructor_WithSeed) {
    uint64_t seed = 0x123456789ABCDEF0;
    EXPECT_NO_THROW({
        RD mode(seed);
    });
}

TEST_F(RandomDeltaModeTest, Constructor_ZeroSeed_UsesRandom) {
    EXPECT_NO_THROW({
        RD mode(0);
    });
}

TEST_F(RandomDeltaModeTest, EncryptDecrypt_SingleBlock) {
    RD mode(12345);
    
    Bytes plaintext = generate_random_data(bs);
    Bytes ciphertext;
    Bytes decrypted;
    
    mode.encrypt(*cipher, plaintext, ciphertext, 1);
    mode.decrypt(*cipher, ciphertext, decrypted, 1);
    
    EXPECT_TRUE(are_bytes_equal(plaintext, decrypted));
}

TEST_F(RandomDeltaModeTest, EncryptDecrypt_MultipleBlocks) {
    RD mode(12345);
    
    std::vector<size_t> block_counts = {1, 2, 5, 10, 20};
    
    for (size_t num_blocks : block_counts) {
        Bytes plaintext = generate_random_data(bs * num_blocks);
        Bytes ciphertext;
        Bytes decrypted;
        
        mode.encrypt(*cipher, plaintext, ciphertext, 1);
        
        EXPECT_EQ(ciphertext.size(), plaintext.size() + 2 * bs);
        
        mode.decrypt(*cipher, ciphertext, decrypted, 1);
        
        EXPECT_EQ(decrypted.size(), plaintext.size());
        EXPECT_TRUE(are_bytes_equal(plaintext, decrypted))
            << "Failed for " << num_blocks << " blocks";
    }
}

TEST_F(RandomDeltaModeTest, SameSeed_SameCiphertext) {
    uint64_t seed = 12345;
    
    RD mode1(seed);
    RD mode2(seed);
    
    Bytes plaintext = generate_random_data(bs * 5);
    Bytes ciphertext1, ciphertext2;
    
    mode1.encrypt(*cipher, plaintext, ciphertext1, 1);
    mode2.encrypt(*cipher, plaintext, ciphertext2, 1);
    
    EXPECT_EQ(ciphertext1.size(), ciphertext2.size());
    EXPECT_TRUE(are_bytes_equal(ciphertext1, ciphertext2));
}

TEST_F(RandomDeltaModeTest, DifferentSeeds_DifferentCiphertext) {
    RD mode1(12345);
    RD mode2(54321);
    
    Bytes plaintext = generate_random_data(bs * 5);
    Bytes ciphertext1, ciphertext2;
    
    mode1.encrypt(*cipher, plaintext, ciphertext1, 1);
    mode2.encrypt(*cipher, plaintext, ciphertext2, 1);
    
    EXPECT_FALSE(are_bytes_equal(ciphertext1, ciphertext2));
}

TEST_F(RandomDeltaModeTest, Encrypt_NonAlignedInput_Throws) {
    RD mode(12345);
    
    Bytes plaintext_not_aligned = generate_random_data(bs * 3 + 1);
    Bytes ciphertext;
    
    EXPECT_THROW({
        mode.encrypt(*cipher, plaintext_not_aligned, ciphertext, 1);
    }, std::invalid_argument);
}

TEST_F(RandomDeltaModeTest, Decrypt_InvalidCiphertextSize_Throws) {
    RD mode(12345);
    
    Bytes invalid_ciphertext_too_small = generate_random_data(bs * 2);
    Bytes decrypted;
    
    EXPECT_THROW({
        mode.decrypt(*cipher, invalid_ciphertext_too_small, decrypted, 1);
    }, std::invalid_argument);
    
    Bytes invalid_ciphertext_not_aligned = generate_random_data(bs * 3 + 1);
    
    EXPECT_THROW({
        mode.decrypt(*cipher, invalid_ciphertext_not_aligned, decrypted, 1);
    }, std::invalid_argument);
}

TEST_F(RandomDeltaModeTest, Decrypt_ManipulatedMetadata_Fails) {
    RD mode(12345);
    
    Bytes plaintext = generate_random_data(bs * 3);
    Bytes ciphertext;
    Bytes decrypted;
    
    mode.encrypt(*cipher, plaintext, ciphertext, 1);
    
    Bytes corrupted = ciphertext;
    corrupted[3] ^= 0xFF;
    
    mode.decrypt(*cipher, corrupted, decrypted, 1);
    
    EXPECT_FALSE(are_bytes_equal(plaintext, decrypted));
}

} // namespace testing
} // namespace crypto