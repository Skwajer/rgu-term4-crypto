#include "TemplateProbabilisticPrimalityTest.hpp"
#include <cmath>
#include <cstddef>
#include <stdexcept>

TemplateProbSimplicityTest::~TemplateProbSimplicityTest() 
{}

bool TemplateProbSimplicityTest::isPerfectSquare(BigInt const &n) 
    {
        if (n < 2) return false;
        BigInt sqrtN = static_cast<BigInt>(boost::multiprecision::sqrt(n));
        return (sqrtN * sqrtN == n);
    }

bool TemplateProbSimplicityTest::is_prime(BigInt const &n, double target_prob)
{
    if (n <= 0) {throw std::invalid_argument("n must be > 0");}
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