#include "FermatPrimalityTest.hpp"
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/multiprecision/random.hpp>
#include <iostream>
#include <ctime>


bool FermatPrimalityTest::perform_single_iteration(BigInt const &n)
{
    static boost::random::mt19937 rng(static_cast<unsigned>(std::time(nullptr)));
    
    BigInt a;
    
    size_t n_bits = boost::multiprecision::msb(n) + 1;
    
    do {
        a = 0;
        size_t words = (n_bits + 63) / 64 + 1;
        
        for (size_t i = 0; i < words; ++i) {
            a <<= 64;
            a |= rng();
        }
        
        if (n > 3) {
            a = a % (n - 3) + 2;
        } else {
            a = 2;
        }
        
    } while (a < 2 || a > n - 2);
    
    BigInt result = NumberTheoryService::pow_mod(a, n-1, n);
    return result == 1;
}