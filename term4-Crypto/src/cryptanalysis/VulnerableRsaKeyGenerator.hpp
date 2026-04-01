#pragma once
#include <boost/multiprecision/cpp_int.hpp>
//#include <boost/multiprecision/cpp_bin_float.hpp>
//#include <boost/multiprecision/fwd.hpp>
#include <random>
#include <memory>


using BigInt = boost::multiprecision::cpp_int;

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

struct rsaVulnerableKeys
{
    public_key pub_key;
    private_key priv_key;
};

class VulnerableRsaKeyGenerator
{
public:
    static BigInt generate_prime(
        size_t bits_count, double target_prob);

    static rsaVulnerableKeys generate_vulnerable_to_Fermat_attack(
        size_t bits_count, double target_prob);

    static rsaVulnerableKeys generate_vulnerable_to_Wieners_attack(
        size_t bits_count, double target_prob);

private:
    static BigInt generate_candidate(
        size_t bits);

    static BigInt find_next_prime(
        BigInt prime, double target_prob);

    static BigInt choose_public_exponent(
        const BigInt& phi_n);

    static bool is_vulnerable_to_Wieners_attack(
        const BigInt& d, const BigInt& n);
};