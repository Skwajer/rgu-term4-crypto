#include "IProbabilisticPrimalityTest.hpp"
#include <boost/multiprecision/integer.hpp>
#include <cstddef>


class TemplateProbSimplicityTest : IProbSimplicityTest
{
public:
    virtual ~TemplateProbSimplicityTest() = default;
    bool is_prime(BigInt const &n, double target_prob) override;

public:
    size_t calculate_iters(double target_prob);

protected:
    virtual bool perform_single_iteration(BigInt const &n) = 0;

private:
    bool isPerfectSquare(BigInt const &n) 
    {
        if (n < 2) return false;
        BigInt sqrtN = static_cast<BigInt>(boost::multiprecision::sqrt(n));
        return (sqrtN * sqrtN == n);
    }
};