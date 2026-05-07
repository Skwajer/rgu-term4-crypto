#include "DSA.hpp"
#include "../../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.hpp"

BigInt DSA::hash_message(
    const std::vector<uint8_t>& message
)
{
    BigInt hash = 0;

    for (uint8_t byte : message)
    {
        hash = (hash * 257 + byte);
    }

    return hash;
}

BigInt DSA::generate_q(
    size_t bits,
    double prob
)
{
    return NumberTheoryService::generate_prime(
        bits,
        prob
    );
}

BigInt DSA::generate_p(
    const BigInt& q,
    size_t bits,
    double prob
)
{
    while (true)
    {
        BigInt min_k =
            BigInt(1) << (bits - 161);

        BigInt max_k =
            BigInt(1) << (bits - 160);

        BigInt k =
            NumberTheoryService::generate_random_bigint(
                min_k,
                max_k
            );

        BigInt p = k * q + 1;

        static MillerRabinPrimalityTest primality_test;
        if (primality_test.is_prime(p, prob))
        {
            return p;
        }
    }
}


BigInt DSA::generate_g(
    const BigInt& p,
    const BigInt& q
)
{
    BigInt exponent =
        (p - 1) / q;

    while (true)
    {
        BigInt h =
            NumberTheoryService::generate_random_bigint(
                2,
                p - 2
            );

        BigInt g =
            NumberTheoryService::pow_mod(
                h,
                exponent,
                p
            );

        if (g > 1)
        {
            return g;
        }
    }
}

void DSA::generate_keys(
    size_t p_bits,
    size_t q_bits,
    double prob
)
{
    q = generate_q(
        q_bits,
        prob
    );

    p = generate_p(
        q,
        p_bits,
        prob
    );

    g = generate_g(
        p,
        q
    );

    x =
        NumberTheoryService::generate_random_bigint(
            1,
            q - 1
        );

    y =
        NumberTheoryService::pow_mod(
            g,
            x,
            p
        );
}

DSASignature DSA::sign(
    const std::vector<uint8_t>& message
) const
{
    BigInt h =
        hash_message(message) % q;

    while (true)
    {
        BigInt k =
            NumberTheoryService::generate_random_bigint(
                1,
                q - 1
            );

        if (NumberTheoryService::gcd(k, q) != 1)
        {
            continue;
        }

        BigInt r =
            NumberTheoryService::pow_mod(
                g,
                k,
                p
            ) % q;

        if (r == 0)
        {
            continue;
        }

        BigInt k_inv =
            NumberTheoryService::get_inv(
                k,
                q
            );

        BigInt s =
            (k_inv * (h + x * r)) % q;

        if (s < 0)
        {
            s += q;
        }

        if (s == 0)
        {
            continue;
        }

        return {r, s};
    }
}

bool DSA::verify(
    const std::vector<uint8_t>& message,
    const DSASignature& signature
) const
{
    const BigInt& R = signature.r;
    const BigInt& S = signature.s;

    if (R <= 0 || R >= q)
    {
        return false;
    }

    if (S <= 0 || S >= q)
    {
        return false;
    }

    BigInt h =
        hash_message(message) % q;

    BigInt inv_S =
        NumberTheoryService::get_inv(
            S,
            q
        );

    BigInt A =
        (h * inv_S) % q;

    BigInt B =
        (R * inv_S) % q;

    BigInt V =
        (
            NumberTheoryService::pow_mod(
                g,
                A,
                p
            )
            *
            NumberTheoryService::pow_mod(
                y,
                B,
                p
            )
        ) % p;

    V %= q;

    return V == R;
}

BigInt DSA::getP() const
{
    return p;
}

BigInt DSA::getQ() const
{
    return q;
}

BigInt DSA::getG() const
{
    return g;
}

BigInt DSA::getY() const
{
    return y;
}

BigInt DSA::getX() const
{
    return x;
}