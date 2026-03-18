#include "NumberTheoryService.hpp"

class IProbSimplicityTest
{
public:
    virtual ~IProbSimplicityTest() = default;
    virtual bool is_prime(BigInt const &n, double target_prob) = 0;
};