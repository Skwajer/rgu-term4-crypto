#include "../NumberTheoryService.hpp"
#include "../TemplateProbabilisticPrimalityTest.hpp"
#include <boost/random.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_device.hpp>


class MillerRabinPrimalityTest : public TemplateProbSimplicityTest
{
public:
    MillerRabinPrimalityTest() = default;
    ~MillerRabinPrimalityTest() override = default;

public:
    size_t calculate_iters(double target_prob) override;

public:
    bool perform_single_iteration(BigInt const &n) override;
};