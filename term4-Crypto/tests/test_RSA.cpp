#include <gtest/gtest.h>
#include "../src/crypto_core/rsa/RSA.hpp"
#include "../src/crypto_core/rsa/RsaKeyGeneration.hpp"
#include <vector>

class RSATest : public ::testing::Test {
protected:
    void SetUp() override {
        keys = KeyGeneration::generate(1024, 0.999);
    }

    rsaKeys keys;
};

TEST_F(RSATest, EncryptDecryptMultipleShortMessages) {
    std::vector<Bytes> test_messages = {
        {'A'},

        {'H', 'i'},

        {'1', '2', '3'},

        {'T', 'e', 's', 't'},

        {'H', 'e', 'l', 'l', 'o'},

        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06},

        {'!', '@', '#', '$', '%', '^', '&', 0x01, 0x02, 0x03, 0x04, 0x05,
             0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02,
              0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, '!', '@', '#', '$', '%', '^', '&', '!', '@', '#', '$', '%', '^', '&',
            '!', '@', '#', '$', '%', '^', '&','!', 
            '@', '#', '$', '%', '^', '&','!', '@', '#', '$', '%', '^', '&','!', '@', '#', '$', '%', '^', '&'}
    };

    for (size_t i = 0; i < test_messages.size(); ++i) 
    {
        const auto& original = test_messages[i];

        Bytes cipher = RSA::encrypt(original, keys.pub_key);

        Bytes decrypted = RSA::decrypt(cipher, keys.priv_key);

        decrypted.erase(decrypted.begin(), 
                        decrypted.begin() + (decrypted.size() - original.size()));

        EXPECT_EQ(original, decrypted);
    }
}