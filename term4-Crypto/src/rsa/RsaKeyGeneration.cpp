#include "RsaKeyGeneration.hpp"
#include <boost/multiprecision/detail/default_ops.hpp>

BigInt KeyGeneration::generate_candidate(size_t bits)
{
    static boost::random::mt19937_64 rng(std::random_device{}());

    BigInt n = 0;

    size_t words = (bits + 63) / 64;

    for (size_t i = 0; i < words; ++i)
    {
        n <<= 64;
        n |= rng();
    }

    size_t extra_bits = words * 64 - bits;
    if (extra_bits > 0)
    {
        n >>= extra_bits;
    }

    n |= (BigInt(1) << (bits - 1));
    n |= 1;

    return n;
}

BigInt KeyGeneration::generate_prime(size_t bits_count, double target_prob)
{
    if (target_prob <= 0 || target_prob >= 1)
    {
        throw std::invalid_argument("the target probability should be in (0 ; 1)");
    }

    auto primality_test = std::make_unique<MillerRabinPrimalityTest>();

    BigInt p = generate_candidate(bits_count);

    while (!(primality_test->is_prime(p, target_prob)))
    {
        p += 2;

        if (boost::multiprecision::msb(p) + 1 > bits_count)
        {
            p = generate_candidate(bits_count);
        }
    }

    return p;
}

bool KeyGeneration::is_vulnerable_to_Wieners_attack(const BigInt& d, const BigInt& n)
{
    BigInt root4 = boost::multiprecision::sqrt(boost::multiprecision::sqrt(n));
    return d < (root4 / 3);
}

BigInt KeyGeneration::choose_public_exponent(const BigInt& phi_n)
{
    static const int exponents[] = {65537, 257, 17, 5, 3};

    for (int e_val : exponents)
    {
        BigInt e = e_val;

        if (NumberTheoryService::gcd(e, phi_n) == 1)
        {
            return e;
        }
    }

    throw std::runtime_error("Failed to find suitable public exponent");
}

rsaKeys KeyGeneration::generate(size_t bits_count, double target_prob)
{
    BigInt p;
    BigInt q;
    BigInt n;
    BigInt phi_n;
    BigInt e, d;

    while (true)
    {
        p = generate_prime(bits_count / 2, target_prob);
        q = generate_prime(bits_count / 2, target_prob);

        if (boost::multiprecision::abs(p - q) < (BigInt(1) << (bits_count / 4)))
        {
            continue;
        }

        n = p * q;
        phi_n = (p - 1) * (q - 1);

        e = choose_public_exponent(phi_n);
        std::cout << "gcd(e, phi_n) = " << NumberTheoryService::gcd(e, phi_n) << std::endl;
        d = NumberTheoryService::get_inv(e, phi_n);
        std::cout << "d = " << d << std::endl;

        if (is_vulnerable_to_Wieners_attack(d, n))
        {
            continue;
        }

        break;
    }

    return {{e, n}, {d, n}};
}