#include "../TemplateProbabilisticPrimalityTest.hpp"
#include <boost/random.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_device.hpp>


class FermatPrimalityTest : public TemplateProbSimplicityTest
{
public:

    FermatPrimalityTest() = default;
    ~FermatPrimalityTest() override = default;

private:
    bool perform_single_iteration(BigInt const &n) override;
    size_t calculate_iters(double target_prob) override;

    boost::random::mt19937 m_rng;
};
