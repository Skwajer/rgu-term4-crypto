#ifndef RABIN_CRYPTOSYSTEM_HPP
#define RABIN_CRYPTOSYSTEM_HPP

#include "../../math/NumberTheoryService.hpp"

#include <cstdint>
#include <vector>

class RabinCryptosystem
{
private:
    BigInt p;
    BigInt q;
    BigInt n;
    BigInt B;

    static constexpr size_t DEFAULT_KEY_SIZE = 512;

    static constexpr uint8_t PREFIX_MARKER = 0xAA;
    static constexpr uint8_t SUFFIX_MARKER = 0x55;

    static BigInt generate_blum_prime(size_t bits_count, double target_prob);

    static BigInt bytes_to_bigint(const std::vector<uint8_t>& bytes);

    static std::vector<uint8_t> bigint_to_bytes(
        const BigInt& num,
        size_t min_size = 0
    );

    static size_t bigint_byte_size(const BigInt& num);

    static BigInt sqrt_mod_blum_prime(
        const BigInt& a,
        const BigInt& p
    );

    static BigInt crt(
        const BigInt& a1,
        const BigInt& a2,
        const BigInt& m1,
        const BigInt& m2
    );

public:
    RabinCryptosystem();

    void generateKeys(
        size_t bits_count = DEFAULT_KEY_SIZE,
        double target_prob = 0.999
    );

    void setKeys(
        const BigInt& p_key,
        const BigInt& q_key,
        const BigInt& n_key,
        const BigInt& B_key = 0
    );

    std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext
    );

    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext
    );

    BigInt getPublicKey() const;
    BigInt getPrivateKeyP() const;
    BigInt getPrivateKeyQ() const;
    BigInt getB() const;
};

#endif