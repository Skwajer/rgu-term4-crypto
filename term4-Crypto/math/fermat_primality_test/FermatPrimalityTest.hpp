#include "../TemplateProbabilisticPrimalityTest.hpp"
#include <boost/random.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_device.hpp>


class FermatPrimalityTest : public TemplateProbSimplicityTest
{
public:

    FermatPrimalityTest() = default;
    ~FermatPrimalityTest() override = default;

//public:
    //bool is_prime(BigInt const &n, double target_prob) override;

private:
    bool perform_single_iteration(BigInt const &n) override;
    boost::random::mt19937 m_rng;
};
