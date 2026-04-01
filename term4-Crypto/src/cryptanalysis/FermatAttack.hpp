#pragma once
#include "VulnerableRsaKeyGenerator.hpp"
#include <utility>

static std::pair<BigInt, BigInt> FermatAttack_to_RsaKey(BigInt N)
{
    if (N % 2 == 0)
    {
        return std::make_pair(2, N / 2);
    }
    BigInt a = boost::multiprecision::sqrt(N);
    if (a * a < N)
    {
        a += 1;
    }

    while (true)
    {
        BigInt b_square = a*a - N;
        if (b_square < 0)
        {
            a += 1;
            continue;
        }
        BigInt b = boost::multiprecision::sqrt(b_square);
        if (b * b == b_square)
        {
            return std::make_pair(a + b, a - b);
        }
        a += 1;
    }
}