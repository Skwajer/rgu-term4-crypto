#include <gtest/gtest.h>
#include "../src/DSA/DSA.hpp"

#include <string>
#include <vector>

class DSATest : public ::testing::Test
{
protected:
    DSA dsa;

    void SetUp() override
    {
        dsa.generate_keys(512, 160, 0.999);
    }

    std::vector<uint8_t> to_bytes(
        const std::string& str
    )
    {
        return std::vector<uint8_t>(
            str.begin(),
            str.end()
        );
    }
};

TEST_F(DSATest, SignAndVerifyShortMessage)
{
    std::string text = "Hello DSA";

    auto message = to_bytes(text);

    DSASignature signature =
        dsa.sign(message);

    EXPECT_TRUE(
        dsa.verify(message, signature)
    );
}

TEST_F(DSATest, SignAndVerifyLongMessage)
{
    std::string text =
        "This is message for DSA signing test. "
        "It should verify correctly pupupupuppupupupupupupupupupupupupupupupupup"
;

    auto message = to_bytes(text);

    DSASignature signature =
        dsa.sign(message);

    EXPECT_TRUE(
        dsa.verify(message, signature)
    );
}

TEST_F(DSATest, SignAndVerifyBinaryData)
{
    std::vector<uint8_t> message =
    {
        0x00, 0x01, 0x02, 0x03,
        0xFF, 0xFE, 0xFD, 0xFC,
        0xAA, 0xBB, 0xCC
    };

    DSASignature signature =
        dsa.sign(message);

    EXPECT_TRUE(
        dsa.verify(message, signature)
    );
}

TEST_F(DSATest, ModifiedMessageFailsVerification)
{
    auto original =
        to_bytes("Original message");

    auto modified =
        to_bytes("Modified message");

    DSASignature signature =
        dsa.sign(original);

    EXPECT_FALSE(
        dsa.verify(modified, signature)
    );
}

TEST_F(DSATest, ModifiedSignatureFailsVerification)
{
    auto message =
        to_bytes("Test message");

    DSASignature signature =
        dsa.sign(message);

    signature.r += 1;

    EXPECT_FALSE(
        dsa.verify(message, signature)
    );
}

TEST_F(DSATest, ModifiedSignatureSFailsVerification)
{
    auto message =
        to_bytes("Another test");

    DSASignature signature =
        dsa.sign(message);

    signature.s += 1;

    EXPECT_FALSE(
        dsa.verify(message, signature)
    );
}

TEST_F(DSATest, EmptyMessage)
{
    std::vector<uint8_t> message;

    DSASignature signature =
        dsa.sign(message);

    EXPECT_TRUE(
        dsa.verify(message, signature)
    );
}

TEST_F(DSATest, MultipleSignaturesDiffer)
{
    auto message =
        to_bytes("Same message");

    DSASignature sig1 =
        dsa.sign(message);

    DSASignature sig2 =
        dsa.sign(message);

    /*
        The signatures should be different
    */
    bool same =
        (sig1.r == sig2.r) &&
        (sig1.s == sig2.s);

    EXPECT_FALSE(same);

    EXPECT_TRUE(
        dsa.verify(message, sig1)
    );

    EXPECT_TRUE(
        dsa.verify(message, sig2)
    );
}

TEST_F(DSATest, GeneratedParametersAreValid)
{
    BigInt p = dsa.getP();
    BigInt q = dsa.getQ();
    BigInt g = dsa.getG();
    BigInt y = dsa.getY();
    BigInt x = dsa.getX();

    EXPECT_GT(p, q);
    EXPECT_GT(g, 1);
    EXPECT_LT(g, p);

    EXPECT_GT(x, 0);
    EXPECT_LT(x, q);

    EXPECT_EQ(
        NumberTheoryService::pow_mod(g, x, p),
        y
    );

    EXPECT_EQ(
        (p - 1) % q,
        0
    );
}

TEST_F(DSATest, InvalidRRejected)
{
    auto message =
        to_bytes("Test");

    DSASignature sig =
        dsa.sign(message);

    sig.r = 0;

    EXPECT_FALSE(
        dsa.verify(message, sig)
    );
}

TEST_F(DSATest, InvalidSRejected)
{
    auto message =
        to_bytes("Test");

    DSASignature sig =
        dsa.sign(message);

    sig.s = 0;

    EXPECT_FALSE(
        dsa.verify(message, sig)
    );
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(
        &argc,
        argv
    );

    return RUN_ALL_TESTS();
}