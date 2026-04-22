#include "ElGamalKeyGeneration.hpp"
#include <boost/random/uniform_int_distribution.hpp>
#include <cstddef>
#include <cstdlib>
#include <random>
#include <stdexcept>

namespace ElGamal 
{
    BigInt KeyGeneration::generate_candidate(size_t bits)
    {
        static boost::random::mt19937 rng(std::random_device{}());
        BigInt min_val = BigInt(1) << (bits - 1);
        BigInt max_val = (BigInt(1) << bits) - 1;
        
        boost::random::uniform_int_distribution<BigInt> dist(min_val, max_val);
        BigInt n = dist(rng);

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

        static MillerRabinPrimalityTest primality_test;

        BigInt p = generate_candidate(bits_count);

        while (!(primality_test.is_prime(p, target_prob)))
        {
            p += 2;

            if (boost::multiprecision::msb(p) + 1 > bits_count)
            {
                p = generate_candidate(bits_count);
            }
        }

        return p;
    }

    

    BigInt KeyGeneration::find_primitive_root(BigInt const &p)
    {
        BigInt phi = p - 1;
        BigInt q = phi >> 1;

        for (BigInt g = 2; g < p; ++g)
        {
            if (NumberTheoryService::gcd(g, p) != 1)
            {
                continue;
            }
            if (NumberTheoryService::pow_mod(g, 2, p) == 1)
            {
                continue;
            }
            if (NumberTheoryService::pow_mod(g, q, p) == 1)
            {
                continue;
            }
            return g;
        }
        
        throw std::runtime_error("There is no primitive root of one");
    }

    BigInt KeyGeneration::find_simply_factored_prime(size_t bits_count)
    {
        static MillerRabinPrimalityTest primality_test;
        size_t i = 1;
        while (true)
        {
            BigInt q = generate_prime(bits_count - i, 0.99);
            BigInt p = 2 * q + 1;
            if (primality_test.is_prime(p, 0.99))
            {
                return p;
            }
            i+= 2;
        }

    }

    KeyGeneration::ElGamalKeys KeyGeneration::generate(size_t bits_count, double target_prob)
    {
        BigInt p = find_simply_factored_prime(bits_count);
        BigInt g = find_primitive_root(p);
        BigInt min = 2;
        BigInt max = p - 2;

        boost::random::mt19937 rng(std::random_device{}());
        boost::random::uniform_int_distribution<BigInt> dist(min, max);
        BigInt x = dist(rng);
        BigInt y = NumberTheoryService::pow_mod(g, x, p);
        
        return {{y, g, p}, {x, p}};
    }
}