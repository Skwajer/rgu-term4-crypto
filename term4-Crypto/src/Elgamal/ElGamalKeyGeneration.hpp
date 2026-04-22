#include "../../math/NumberTheoryService.hpp"
#include "../../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.hpp"
#include "random"
#include "memory"

namespace ElGamal 
{
    class KeyGeneration
    {
    public:
        struct public_key
            {
                BigInt y;
                BigInt g;
                BigInt p;
            };

            struct private_key
            {
                BigInt x;
                BigInt p;
            };

        struct ElGamalKeys
        {
            public_key pub_key;
            private_key priv_key;
        };

    private:
        static BigInt generate_candidate(size_t bits);

        static BigInt generate_prime(size_t bits_count, double target_prob);

        static BigInt find_primitive_root(BigInt const &num);

        static BigInt find_simply_factored_prime(size_t bits_count);

    public:
        static ElGamalKeys generate(size_t bits_count, double target_prob);
    };
}