#include "SolovayStrassenPrimalityTest.hpp"
#include <boost/random/random_device.hpp>
#include <cmath>
#include <ctime>
#include <random>

size_t SolovayStrassenPrimalityTest::calculate_iters(double target_prob)
{
    if (target_prob <= 0.0 || target_prob >= 1.0) {
        throw std::invalid_argument("the probability should be in fractions of a one");
    }
    
    double error_prob = 1.0 - target_prob;
    
    double log_value = std::log(error_prob) / std::log(0.5);
    size_t iters = static_cast<size_t>(std::ceil(log_value));
    return std::max<size_t>(iters, 1);
}

bool SolovayStrassenPrimalityTest::perform_single_iteration(BigInt const &n)
{
    static boost::random::mt19937_64 rng(std::random_device{}());
    
    BigInt a;
    
    size_t n_bits = boost::multiprecision::msb(n) + 1;
    
    do 
    {
        a = 0;
        size_t words = (n_bits + 63) / 64 + 1;
        BigInt range = n - 3;
        BigInt limit_for_sampling = n - (n % range);
        
        for (size_t i = 0; i < words; ++i) 
        {
            a <<= 64;
            a |= rng();
        }
        a = a % (n - 3) + 2;
        
    } while (a < 2 || a > n - 2);
    
    BigInt gcd = NumberTheoryService::gcd(a, n);
    if (gcd != 1) {return false;}
    BigInt JacobiSymb = NumberTheoryService::computeJacobiSymbol(a, n); 
    if (NumberTheoryService::pow_mod(a, (n-1)/2, n) != JacobiSymb)
    {
        return false;
    }
    
    return true;
}