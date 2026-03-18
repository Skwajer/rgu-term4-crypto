#include "FermatPrimalityTest.hpp"
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

bool FermatPrimalityTest::perform_single_iteration(BigInt const &n)
{
    boost::random_device rd;
    boost::random::uniform_int_distribution<BigInt> dist(1, n-1);
    BigInt m_pow = NumberTheoryService::pow_mod(dist(rd), n-1, n);
    return m_pow == 1;
}