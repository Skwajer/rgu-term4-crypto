#include <gtest/gtest.h>
#include "../src/rsa/RSA.hpp"
#include "../src/Elgamal/ElgamalCipher.hpp"
#include <utility>
#include <vector>


class ElGamalTest : public ::testing::Test {
protected:
    void SetUp() override {
        keys = ElGamal::KeyGeneration::generate(1024, 0.99);
    }

    ElGamal::KeyGeneration::ElGamalKeys keys;
};

TEST_F(ElGamalTest, compile_test) 
{
    BigInt M = 2354623;
    std::pair<BigInt, BigInt> cipher = ElGamal::ElGamalCipher::encrypt(keys.pub_key, M);
    BigInt decrypted = ElGamal::ElGamalCipher::decrypt(cipher, keys.priv_key);
    EXPECT_EQ(M, decrypted);

}