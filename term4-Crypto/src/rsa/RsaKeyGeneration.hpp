#pragma once

#include "../../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.hpp"
#include <boost/io_fwd.hpp>
#include <boost/multiprecision/integer.hpp>
#include <memory>
#include <random>

struct public_key
{
    BigInt e;
    BigInt N;
};

struct private_key
{
    BigInt d;
    BigInt N;
};

struct rsaKeys
{
    public_key pub_key;
    private_key priv_key;
};

class KeyGeneration
{
private:
    static BigInt generate_candidate(size_t bits);

    static BigInt generate_prime(size_t bits_count, double target_prob);

    static bool is_vulnerable_to_Wieners_attack(const BigInt& d, const BigInt& n);

    static BigInt choose_public_exponent(const BigInt& phi_n);

public:
    static rsaKeys generate(size_t bits_count, double target_prob);
};