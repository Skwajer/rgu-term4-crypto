#ifndef DSA_HPP
#define DSA_HPP

#include "../../math/NumberTheoryService.hpp"

#include <vector>
#include <cstdint>

struct DSASignature
{
    BigInt r;
    BigInt s;
};

class DSA
{
private:
    BigInt p;
    BigInt q;
    BigInt g;

    BigInt x;
    BigInt y;

    static BigInt hash_message(
        const std::vector<uint8_t>& message
    );

    static BigInt generate_q(
        size_t bits,
        double prob
    );

    static BigInt generate_p(
        const BigInt& q,
        size_t bits,
        double prob
    );

    static BigInt generate_g(
        const BigInt& p,
        const BigInt& q
    );

public:
    void generate_keys(
        size_t p_bits = 512,
        size_t q_bits = 160,
        double prob = 0.999
    );

    DSASignature sign(
        const std::vector<uint8_t>& message
    ) const;

    bool verify(
        const std::vector<uint8_t>& message,
        const DSASignature& signature
    ) const;

    BigInt getP() const;
    BigInt getQ() const;
    BigInt getG() const;
    BigInt getY() const;
    BigInt getX() const;
};

#endif