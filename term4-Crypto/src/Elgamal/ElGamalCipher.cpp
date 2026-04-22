#include "ElgamalCipher.hpp"
#include <stdexcept>

namespace ElGamal {
    std::pair<BigInt, BigInt> ElGamalCipher::encrypt(KeyGeneration::public_key const &pkey, BigInt M)
    {
        if (M >= pkey.p)
        {
            throw std::invalid_argument("Message must be less then p");
        }

        BigInt k = NumberTheoryService::generate_random_bigint(1, pkey.p - 2);
        BigInt a = NumberTheoryService::pow_mod(pkey.g, k, pkey.p);
        BigInt b = NumberTheoryService::pow_mod(pkey.y, k, pkey.p);
        b = (b * M) % pkey.p;
        return {a, b};
    }

    BigInt ElGamalCipher::decrypt(std::pair<BigInt, BigInt> cipher, KeyGeneration::private_key const &privkey)
    {
        BigInt M = cipher.second * NumberTheoryService::pow_mod(cipher.first, privkey.p - 1 - privkey.x, privkey.p);
        return M % privkey.p;
    }
}