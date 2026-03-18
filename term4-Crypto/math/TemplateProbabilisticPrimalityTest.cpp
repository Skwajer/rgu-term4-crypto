#include "TemplateProbabilisticPrimalityTest.hpp"
#include <cmath>
#include <cstddef>


size_t TemplateProbSimplicityTest::calculate_iters(double target_prob)
{
    double error_prob = 1 - target_prob;
    size_t iters = static_cast<size_t>(std::ceil(log2(error_prob)));
    return iters;
}

bool TemplateProbSimplicityTest::is_prime(BigInt const &n, double target_prob)
{
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