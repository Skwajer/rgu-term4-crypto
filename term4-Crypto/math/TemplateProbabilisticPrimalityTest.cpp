#include "TemplateProbabilisticPrimalityTest.hpp"
#include <cmath>
#include <cstddef>

TemplateProbSimplicityTest::~TemplateProbSimplicityTest() 
{}

size_t TemplateProbSimplicityTest::calculate_iters(double target_prob)
{
    if (target_prob <= 0.0 || target_prob >= 1.0) {
        return 10; 
    }
    
    double error_prob = 1.0 - target_prob;
    
    if (error_prob <= 0.0) {
        return 100;
    }
    
    double log_value = std::log2(1.0 / error_prob);
    size_t iters = static_cast<size_t>(std::ceil(log_value));
    
    return std::max<size_t>(iters, 1);
}

bool TemplateProbSimplicityTest::isPerfectSquare(BigInt const &n) 
    {
        if (n < 2) return false;
        BigInt sqrtN = static_cast<BigInt>(boost::multiprecision::sqrt(n));
        return (sqrtN * sqrtN == n);
    }

bool TemplateProbSimplicityTest::is_prime(BigInt const &n, double target_prob)
{
    if (n == 1) { return false;}
    if (n == 2 || n == 3) { return true;} 
    if (n % 2 == 0) {return false;}
    if (isPerfectSquare(n)) {return false;}
    
    size_t total_iters = calculate_iters(target_prob);

    for (size_t i = 0; i < total_iters; i++)
    {
        if (!perform_single_iteration(n))
        {
            return false;
        }
    }

    return true;
}