#include "../NumberTheoryService.hpp"
#include "../TemplateProbabilisticPrimalityTest.hpp"
#include <boost/random.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_device.hpp>


class SolovayStrassenPrimalityTest : public TemplateProbSimplicityTest
{
public:
    SolovayStrassenPrimalityTest() = default;
    ~SolovayStrassenPrimalityTest() override = default;

public:
    size_t calculate_iters(double target_prob) override;

public:
    bool perform_single_iteration(BigInt const &n) override;
};