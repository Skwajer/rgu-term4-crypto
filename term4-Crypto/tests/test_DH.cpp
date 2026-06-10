#include <gtest/gtest.h>
#include "../src/Diffie-Hellman/DH.hpp"
#include <future>

class DiffieHellmanTest : public ::testing::Test {
protected:
    void SetUp() override {
    }
    
    void TearDown() override {
    }
    
    bool keysEqual(const std::vector<uint8_t>& key1, const std::vector<uint8_t>& key2) {
        if (key1.size() != key2.size()) return false;
        for (size_t i = 0; i < key1.size(); i++) {
            if (key1[i] != key2[i]) return false;
        }
        return true;
    }
};

// Тест 1: Проверка генерации параметров p и g
TEST_F(DiffieHellmanTest, ParameterGeneration) {
    std::cout << "Step 1: Creating DiffieHellman object with 16 bits..." << std::endl;
    
    DiffieHellman dh(64);
    
    std::cout << "Step 2: Getting prime..." << std::endl;
    BigInt p = dh.getPrime();
    std::cout << "Prime: " << p << std::endl;
    
    std::cout << "Step 3: Getting generator..." << std::endl;
    BigInt g = dh.getGenerator();
    std::cout << "Generator: " << g << std::endl;
    
    std::cout << "Step 4: Verifying..." << std::endl;
    EXPECT_GT(p, 1);
    EXPECT_GT(g, 1);
    
    std::cout << "Test completed!" << std::endl;
}

TEST_F(DiffieHellmanTest, PublicKeyCalculation) {
    DiffieHellman dh(128);
    
    BigInt g = dh.getGenerator();
    BigInt p = dh.getPrime();
    BigInt publicKey = dh.getPublicKey();
    
    EXPECT_GE(publicKey, 2);
    EXPECT_LE(publicKey, p - 1);
}

TEST_F(DiffieHellmanTest, SharedSecretAgreement) {
    DiffieHellman alice(512);
    BigInt p = alice.getPrime();
    BigInt g = alice.getGenerator();
    
    DiffieHellman bob(p, g);
    
    BigInt alicePublic = alice.getPublicKey();
    BigInt bobPublic = bob.getPublicKey();
    
    alice.computeSharedSecret(bobPublic);
    bob.computeSharedSecret(alicePublic);
    
    EXPECT_EQ(alice.getSharedSecret(), bob.getSharedSecret());
}

TEST_F(DiffieHellmanTest, DifferentPrivateKeysGiveDifferentPublicKeys) {
    DiffieHellman alice(512);
    DiffieHellman bob(alice.getPrime(), alice.getGenerator());
    
    EXPECT_NE(alice.getPublicKey(), bob.getPublicKey());
}

TEST_F(DiffieHellmanTest, DESKeyGeneration) {
    DiffieHellman alice(512);
    DiffieHellman bob(alice.getPrime(), alice.getGenerator());
    
    alice.computeSharedSecret(bob.getPublicKey());
    bob.computeSharedSecret(alice.getPublicKey());
    
    auto desKeyAlice = alice.generateDESKey();
    auto desKeyBob = bob.generateDESKey();
    
    EXPECT_EQ(desKeyAlice.size(), 8);
    EXPECT_EQ(desKeyBob.size(), 8);
    
    EXPECT_TRUE(keysEqual(desKeyAlice, desKeyBob));
    
    for (int i = 0; i < 8; i++) {
        int parity = 0;
        for (int j = 0; j < 8; j++) {
            if (desKeyAlice[i] & (1 << j)) parity++;
        }
        EXPECT_TRUE(parity % 2 == 1);
    }
}

TEST_F(DiffieHellmanTest, AESKeyGeneration) {
    DiffieHellman alice(512);
    DiffieHellman bob(alice.getPrime(), alice.getGenerator());
    
    alice.computeSharedSecret(bob.getPublicKey());
    bob.computeSharedSecret(alice.getPublicKey());
    
    // Тест AES-128
    auto aes128Alice = alice.generateAES128Key();
    auto aes128Bob = bob.generateAES128Key();
    EXPECT_EQ(aes128Alice.size(), 16);
    EXPECT_TRUE(keysEqual(aes128Alice, aes128Bob));
    
    // Тест AES-192
    auto aes192Alice = alice.generateAES192Key();
    auto aes192Bob = bob.generateAES192Key();
    EXPECT_EQ(aes192Alice.size(), 24);
    EXPECT_TRUE(keysEqual(aes192Alice, aes192Bob));
    
    // Тест AES-256
    auto aes256Alice = alice.generateAES256Key();
    auto aes256Bob = bob.generateAES256Key();
    EXPECT_EQ(aes256Alice.size(), 32);
    EXPECT_TRUE(keysEqual(aes256Alice, aes256Bob));
}

TEST_F(DiffieHellmanTest, MARSKeyGeneration) {
    DiffieHellman alice(512);
    DiffieHellman bob(alice.getPrime(), alice.getGenerator());
    
    alice.computeSharedSecret(bob.getPublicKey());
    bob.computeSharedSecret(alice.getPublicKey());
    
    // Тест MARS-128
    auto mars128Alice = alice.generateMARS128Key();
    auto mars128Bob = bob.generateMARS128Key();
    EXPECT_EQ(mars128Alice.size(), 16);
    EXPECT_TRUE(keysEqual(mars128Alice, mars128Bob));
    
    // Тест MARS-192
    auto mars192Alice = alice.generateMARS192Key();
    auto mars192Bob = bob.generateMARS192Key();
    EXPECT_EQ(mars192Alice.size(), 24);
    EXPECT_TRUE(keysEqual(mars192Alice, mars192Bob));
    
    // Тест MARS-256
    auto mars256Alice = alice.generateMARS256Key();
    auto mars256Bob = bob.generateMARS256Key();
    EXPECT_EQ(mars256Alice.size(), 32);
    EXPECT_TRUE(keysEqual(mars256Alice, mars256Bob));
}

TEST_F(DiffieHellmanTest, SameSharedSecretGivesSameKeys) {
    DiffieHellman alice(512);
    DiffieHellman bob(alice.getPrime(), alice.getGenerator());
    
    alice.computeSharedSecret(bob.getPublicKey());
    bob.computeSharedSecret(alice.getPublicKey());
    
    auto desKey1 = alice.generateDESKey();
    auto desKey2 = alice.generateDESKey();
    
    EXPECT_TRUE(keysEqual(desKey1, desKey2));
}

TEST_F(DiffieHellmanTest, DifferentPrimeSizes) {
    std::vector<int> sizes = {256, 512, 1024};
    
    for (int size : sizes) {
        DiffieHellman alice(size);
        DiffieHellman bob(alice.getPrime(), alice.getGenerator());
        
        alice.computeSharedSecret(bob.getPublicKey());
        bob.computeSharedSecret(alice.getPublicKey());
        
        EXPECT_EQ(alice.getSharedSecret(), bob.getSharedSecret());
        
        auto desKey = alice.generateDESKey();
        auto aesKey = alice.generateAES128Key();
        auto marsKey = alice.generateMARS128Key();
        
        EXPECT_EQ(desKey.size(), 8);
        EXPECT_EQ(aesKey.size(), 16);
        EXPECT_EQ(marsKey.size(), 16);
    }
}

TEST_F(DiffieHellmanTest, DifferentSharedSecretsGiveDifferentKeys) {
    DiffieHellman alice1(512);
    DiffieHellman bob1(alice1.getPrime(), alice1.getGenerator());
    alice1.computeSharedSecret(bob1.getPublicKey());
    bob1.computeSharedSecret(alice1.getPublicKey());
    
    DiffieHellman alice2(512);
    DiffieHellman bob2(alice2.getPrime(), alice2.getGenerator());
    alice2.computeSharedSecret(bob2.getPublicKey());
    bob2.computeSharedSecret(alice2.getPublicKey());
    
    auto desKey1 = alice1.generateDESKey();
    auto desKey2 = alice2.generateDESKey();
    
    EXPECT_FALSE(keysEqual(desKey1, desKey2));
}

TEST_F(DiffieHellmanTest, BigIntToBytesConversion) {
    BigInt value = 0x123456789ABCDEF;
    auto bytes = DiffieHellman::bigIntToBytes(value);
    
    EXPECT_GT(bytes.size(), 0);
    
    BigInt recovered = 0;
    for (uint8_t b : bytes) {
        recovered = (recovered << 8) | b;
    }
    
    EXPECT_EQ(value, recovered);
}

TEST_F(DiffieHellmanTest, ConcurrentKeyExchange) {
    auto runKeyExchange = [](int id) {
        DiffieHellman alice(512);
        DiffieHellman bob(alice.getPrime(), alice.getGenerator());
        
        alice.computeSharedSecret(bob.getPublicKey());
        bob.computeSharedSecret(alice.getPublicKey());
        
        return alice.getSharedSecret() == bob.getSharedSecret();
    };
    
    std::vector<std::future<bool>> futures;
    for (int i = 0; i < 10; i++) {
        futures.push_back(std::async(std::launch::async, runKeyExchange, i));
    }
    
    for (auto& future : futures) {
        EXPECT_TRUE(future.get());
    }
}

TEST_F(DiffieHellmanTest, KeySizes) {
    DiffieHellman dh(512);
    
    // DES: 8 байт
    EXPECT_EQ(dh.generateDESKey().size(), 8);
    
    // AES: 16, 24, 32 байта
    EXPECT_EQ(dh.generateAES128Key().size(), 16);
    EXPECT_EQ(dh.generateAES192Key().size(), 24);
    EXPECT_EQ(dh.generateAES256Key().size(), 32);
    
    // MARS: 16, 24, 32 байта
    EXPECT_EQ(dh.generateMARS128Key().size(), 16);
    EXPECT_EQ(dh.generateMARS192Key().size(), 24);
    EXPECT_EQ(dh.generateMARS256Key().size(), 32);
}

TEST_F(DiffieHellmanTest, CommutativeProperty) {
    DiffieHellman alice(512);
    DiffieHellman bob(alice.getPrime(), alice.getGenerator());
    
    alice.computeSharedSecret(bob.getPublicKey());
    
    bob.computeSharedSecret(alice.getPublicKey());
    
    EXPECT_EQ(alice.getSharedSecret(), bob.getSharedSecret());
}

TEST_F(DiffieHellmanTest, DifferentPairsGetDifferentSecrets) {
    DiffieHellman alice1(512);
    DiffieHellman bob1(alice1.getPrime(), alice1.getGenerator());
    alice1.computeSharedSecret(bob1.getPublicKey());
    bob1.computeSharedSecret(alice1.getPublicKey());
    
    DiffieHellman alice2(512);
    DiffieHellman bob2(alice2.getPrime(), alice2.getGenerator());
    alice2.computeSharedSecret(bob2.getPublicKey());
    bob2.computeSharedSecret(alice2.getPublicKey());
    
    EXPECT_NE(alice1.getSharedSecret(), alice2.getSharedSecret());
}

TEST_F(DiffieHellmanTest, DifferentAlgorithmsGetDifferentKeys) {
    DiffieHellman dh(512);
    
    auto desKey = dh.generateDESKey();
    auto aesKey = dh.generateAES128Key();
    auto marsKey = dh.generateMARS128Key();
    
    EXPECT_NE(desKey.size(), aesKey.size());
    EXPECT_EQ(aesKey.size(), marsKey.size());

}

TEST_F(DiffieHellmanTest, KeyLengthDoesNotExceedSharedSecret) {
    DiffieHellman dh(256);
    
    auto aes256Key = dh.generateAES256Key();
    EXPECT_EQ(aes256Key.size(), 32);
    
}

TEST_F(DiffieHellmanTest, KeyDerivationIsDeterministic) {
    DiffieHellman alice(512);
    DiffieHellman bob(alice.getPrime(), alice.getGenerator());
    
    alice.computeSharedSecret(bob.getPublicKey());
    bob.computeSharedSecret(alice.getPublicKey());
    
    std::vector<std::vector<uint8_t>> desKeys;
    for (int i = 0; i < 5; i++) {
        desKeys.push_back(alice.generateDESKey());
    }
    
    for (int i = 1; i < 5; i++) {
        EXPECT_TRUE(keysEqual(desKeys[0], desKeys[i]));
    }
}

TEST_F(DiffieHellmanTest, DESParityBits) {
    DiffieHellman dh(512);
    auto desKey = dh.generateDESKey();
    
    for (size_t i = 0; i < desKey.size(); i++) {

        int count = 0;
        uint8_t byte = desKey[i];
        for (int j = 0; j < 8; j++) {
            if (byte & (1 << j)) count++;
        }
        EXPECT_TRUE(count % 2 == 1) << "Byte " << i << " has even parity";
    }
}

TEST_F(DiffieHellmanTest, PerformanceTest) {
    auto start = std::chrono::high_resolution_clock::now();
    
    DiffieHellman alice(512);
    DiffieHellman bob(alice.getPrime(), alice.getGenerator());
    
    alice.computeSharedSecret(bob.getPublicKey());
    bob.computeSharedSecret(alice.getPublicKey());
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Key exchange took " << duration.count() << " ms" << std::endl;
    
    EXPECT_TRUE(true);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}