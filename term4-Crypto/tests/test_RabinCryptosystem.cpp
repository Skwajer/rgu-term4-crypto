#include <gtest/gtest.h>
#include "../src/RabinCryptoSystem/RabinCryptosystem.hpp"
#include <string>

class RabinCryptosystemTest : public ::testing::Test {
protected:
    RabinCryptosystem rabin;
    
    void SetUp() override {
        rabin.generateKeys(512, 0.999);
    }
    
    std::vector<uint8_t> string_to_bytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    std::string bytes_to_string(const std::vector<uint8_t>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }
};

TEST_F(RabinCryptosystemTest, EncryptDecrypt_ShortMessage) {
    std::string original = "Hello, Rabin, epta!";
    std::vector<uint8_t> plaintext = string_to_bytes(original);
    
    std::vector<uint8_t> ciphertext = rabin.encrypt(plaintext);
    std::vector<uint8_t> decrypted = rabin.decrypt(ciphertext);
    
    EXPECT_EQ(plaintext, decrypted);
    EXPECT_EQ(original, bytes_to_string(decrypted));
}

TEST_F(RabinCryptosystemTest, EncryptDecrypt_EmptyMessage) {
    std::vector<uint8_t> plaintext;
    
    std::vector<uint8_t> ciphertext = rabin.encrypt(plaintext);
    std::vector<uint8_t> decrypted = rabin.decrypt(ciphertext);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(RabinCryptosystemTest, EncryptDecrypt_LongMessage) {
    std::string original = "This is a very long message that should be split into multiple blocks. "
                          "We need to test that the block processing works correctly. "
                          "The Rabin cryptosystem should handle arbitrary length messages. "
                          "Let's add some more text to make sure we have enough data. "
                          "Cryptography is fascinating! 1234567890!@#$%^&*()"
                          "Я сейчас сяду за РУЛЬ! А ты вылетИшь ОтСюДА!!!";
    
    std::vector<uint8_t> plaintext = string_to_bytes(original);
    
    std::vector<uint8_t> ciphertext = rabin.encrypt(plaintext);
    std::vector<uint8_t> decrypted = rabin.decrypt(ciphertext);
    
    EXPECT_EQ(plaintext, decrypted);
    EXPECT_EQ(original, bytes_to_string(decrypted));
}

TEST_F(RabinCryptosystemTest, EncryptDecrypt_BinaryData) {
    std::vector<uint8_t> plaintext = {
        0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    
    std::vector<uint8_t> ciphertext = rabin.encrypt(plaintext);
    std::vector<uint8_t> decrypted = rabin.decrypt(ciphertext);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(RabinCryptosystemTest, EncryptionIsProbabilistic) {
    std::string message = "Test message";
    std::vector<uint8_t> plaintext = string_to_bytes(message);
    
    RabinCryptosystem rabin2;
    rabin2.setKeys(rabin.getPrivateKeyP(), 
                   rabin.getPrivateKeyQ(), 
                   rabin.getPublicKey(),
                   rabin.getB());
    
    std::vector<uint8_t> ciphertext1 = rabin.encrypt(plaintext);
    std::vector<uint8_t> ciphertext2 = rabin2.encrypt(plaintext);
    
    std::vector<uint8_t> decrypted1 = rabin.decrypt(ciphertext1);
    std::vector<uint8_t> decrypted2 = rabin2.decrypt(ciphertext2);
    
    EXPECT_EQ(plaintext, decrypted1);
    EXPECT_EQ(plaintext, decrypted2);
}

TEST_F(RabinCryptosystemTest, KeysSatisfyConditions) {
    BigInt p = rabin.getPrivateKeyP();
    BigInt q = rabin.getPrivateKeyQ();
    BigInt n = rabin.getPublicKey();
    BigInt B = rabin.getB();
    
    EXPECT_EQ(p % 4, 3);
    EXPECT_EQ(q % 4, 3);
    
    EXPECT_EQ(n, p * q);
    
    EXPECT_NE(p, q);
    
    EXPECT_EQ(NumberTheoryService::gcd(B, n), 1);
    EXPECT_GT(B, 0);
    EXPECT_LT(B, n);
}

TEST_F(RabinCryptosystemTest, CiphertextSize) {
    std::string message = "Size test message";
    std::vector<uint8_t> plaintext = string_to_bytes(message);
    
    std::vector<uint8_t> ciphertext = rabin.encrypt(plaintext);
    
    EXPECT_GT(ciphertext.size(), 0);
    
    EXPECT_GT(ciphertext.size(), plaintext.size());
}

TEST_F(RabinCryptosystemTest, MultipleEncryptions) {
    for (int i = 0; i < 10; ++i) {
        std::string message = "Iteration " + std::to_string(i);
        std::vector<uint8_t> plaintext = string_to_bytes(message);
        
        std::vector<uint8_t> ciphertext = rabin.encrypt(plaintext);
        std::vector<uint8_t> decrypted = rabin.decrypt(ciphertext);
        
        EXPECT_EQ(plaintext, decrypted);
    }
}

TEST_F(RabinCryptosystemTest, InvalidCiphertextThrows) {
    std::vector<uint8_t> invalid_ciphertext = {0xFF, 0xFF};
    EXPECT_THROW(rabin.decrypt(invalid_ciphertext), std::runtime_error);
}

TEST_F(RabinCryptosystemTest, KeyReset) {
    rabin.generateKeys(512, 0.999);
    BigInt first_p = rabin.getPrivateKeyP();
    BigInt first_q = rabin.getPrivateKeyQ();
    
    rabin.generateKeys(512, 0.999);
    BigInt second_p = rabin.getPrivateKeyP();
    BigInt second_q = rabin.getPrivateKeyQ();
    
    EXPECT_NE(first_p, second_p);
    EXPECT_NE(first_q, second_q);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}