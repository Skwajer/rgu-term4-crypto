#include <gtest/gtest.h>
#include <memory>
#include "../src/cryptanalysis/VulnerableRsaKeyGenerator.hpp"
#include "../src/cryptanalysis/FermatAttack.hpp"

class VulnerableRSAKeysTest : public ::testing::Test {
protected:
    void SetUp() override {
        keys = VulnerableRsaKeyGenerator::generate_vulnerable_to_Fermat_attack(
            2048, 0.999);
    }

    rsaVulnerableKeys keys;
};

TEST_F(VulnerableRSAKeysTest, test1)
{
    BigInt N = keys.pub_key.N;
    auto N_factorization = FermatAttack_to_RsaKey(N);
    EXPECT_EQ(N_factorization.first * N_factorization.second, N);
}