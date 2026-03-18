#include "../TemplateProbabilisticPrimalityTest.hpp"
#include <boost/random.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_device.hpp>


class FermatPrimalityTest : TemplateProbSimplicityTest
{
public:
    FermatPrimalityTest();

//public:
    //bool is_prime(BigInt const &n, double target_prob) override;

private:
    bool perform_single_iteration(BigInt const &n) override;
};
