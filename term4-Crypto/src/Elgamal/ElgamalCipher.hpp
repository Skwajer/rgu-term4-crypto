#include <utility>
#include "../../math/NumberTheoryService.hpp"
#include "ElGamalKeyGeneration.hpp"
namespace ElGamal {
    class ElGamalCipher
    {
    public:
        static std::pair<BigInt, BigInt> encrypt(KeyGeneration::public_key const &pkey, BigInt M);
        static BigInt decrypt(std::pair<BigInt, BigInt> cipher, KeyGeneration::private_key const &privkey);
    };
}