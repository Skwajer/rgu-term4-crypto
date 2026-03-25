#include <gtest/gtest.h>
#include <memory>
#include "../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.hpp"

class MillerRabinPrimalityTestTest : public ::testing::Test {
protected:
    void SetUp() override {
        test = std::make_unique<MillerRabinPrimalityTest>();
    }
    
    std::unique_ptr<MillerRabinPrimalityTest> test;
};


TEST_F(MillerRabinPrimalityTestTest, CheckBigNumber) 
{
    BigInt n("359334085968622831041960188598043661065388726959079837");
    
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, LargePrime) {
    BigInt n("170141183460469231731687303715884105727");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, LargeComposite) {
    BigInt n = BigInt("170141183460469231731687303715884105727") * 3;
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, Prime50Digits1) {
    BigInt n("1340780792994259709957402499820584612747936582059");
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, Prime50Digits2) {
    BigInt n("1095374252562003245721307985673429183740192837461");
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, Composite50Digits1) {
    BigInt n("1340780792994259709957402499820584612747936582059");
    n = n * 7;
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, Composite50Digits2) {
    BigInt n("1095374252562003245721307985673429183740192837461");
    n = n * 11;
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, Prime60Digits1) {
    BigInt n("1461501637330902918203684832716283019655932542981123");
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, PrimeRSA1) {
    BigInt n("37975227936943673922808872755445627854565536638199");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, PrimeRSA2) {
    BigInt n("40094690950920881030683735292761468389214899724061");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, PrimeRSA3) {
    BigInt n("327414555693498015751146303749141488063642403240171463406883");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, PrimeRSA4) {
    BigInt n("693342667110830181197325401899700641361965863127336680673013");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(MillerRabinPrimalityTestTest, CarmichaelNumbers)
{
    BigInt n1("561");
    BigInt n2("41041");
    BigInt n3("825265");
    BigInt n4("321197185");
    BigInt n9("9746347772161");
    EXPECT_FALSE(test->is_prime(n1, 0.999));
    EXPECT_FALSE(test->is_prime(n2, 0.999));
    EXPECT_FALSE(test->is_prime(n3, 0.999));
    EXPECT_FALSE(test->is_prime(n4, 0.999));
    EXPECT_FALSE(test->is_prime(n9, 0.999));
}