#include <gtest/gtest.h>
#include <memory>
#include "../math/Solovay_Strassen_primality_test/SolovayStrassenPrimalityTest.hpp"

class SolovayStrassenPrimalityTestTest : public ::testing::Test {
protected:
    void SetUp() override {
        test = std::make_unique<SolovayStrassenPrimalityTest>();
    }
    
    std::unique_ptr<SolovayStrassenPrimalityTest> test;
};


TEST_F(SolovayStrassenPrimalityTestTest, CheckBigNumber) 
{
    BigInt n("359334085968622831041960188598043661065388726959079837");
    
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, LargePrime) {
    BigInt n("170141183460469231731687303715884105727");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, LargeComposite) {
    BigInt n = BigInt("170141183460469231731687303715884105727") * 3;
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, Prime50Digits1) {
    BigInt n("1340780792994259709957402499820584612747936582059");
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, Prime50Digits2) {
    BigInt n("1095374252562003245721307985673429183740192837461");
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, Composite50Digits1) {
    BigInt n("1340780792994259709957402499820584612747936582059");
    n = n * 7;
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, Composite50Digits2) {
    BigInt n("1095374252562003245721307985673429183740192837461");
    n = n * 11;
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, Prime60Digits1) {
    BigInt n("1461501637330902918203684832716283019655932542981123");
    EXPECT_FALSE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, PrimeRSA1) {
    BigInt n("37975227936943673922808872755445627854565536638199");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, PrimeRSA2) {
    BigInt n("40094690950920881030683735292761468389214899724061");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, PrimeRSA3) {
    BigInt n("327414555693498015751146303749141488063642403240171463406883");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}

TEST_F(SolovayStrassenPrimalityTestTest, PrimeRSA4) {
    BigInt n("693342667110830181197325401899700641361965863127336680673013");
    EXPECT_TRUE(test->is_prime(n, 0.999));
}