#include "IProbabilisticPrimalityTest.hpp"
#include <boost/multiprecision/integer.hpp>
#include <cstddef>


class TemplateProbSimplicityTest : public IProbSimplicityTest
{
public:
    virtual ~TemplateProbSimplicityTest();
public:
    bool is_prime(BigInt const &n, double target_prob) override;

public:
    virtual size_t calculate_iters(double target_prob);

public:
    virtual bool perform_single_iteration(BigInt const &n) = 0;

private:
    bool isPerfectSquare(BigInt const &n);
};