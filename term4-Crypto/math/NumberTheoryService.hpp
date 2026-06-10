#ifndef NUMBER_THEORY_SERVICE_HPP
#define NUMBER_THEORY_SERVICE_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/fwd.hpp>

using BigInt = boost::multiprecision::cpp_int;
using BigFloat = boost::multiprecision::cpp_bin_float_100;

class NumberTheoryService
{
public:
      static BigInt computeLegendreSymbol(BigInt const &a, BigInt const &p);
      static BigInt computeJacobiSymbol(BigInt a, BigInt n);
      static BigInt gcd(BigInt a, BigInt b);
      static BigInt egcd(BigInt a, BigInt b, BigInt &x, BigInt &y);
      static BigInt pow_mod(BigInt a, BigInt degree, BigInt mod);
      static BigInt get_inv(BigInt const &a, BigInt const &n);
      static BigInt Euler_func_definition(BigInt const &p);
      static BigInt Euler_func_factorization(BigInt const &n);
      static BigInt Euler_func_Fourier(BigInt const &n);
      static BigInt generate_candidate(size_t bits);
      static BigInt generate_prime(size_t bits_count, double target_prob);
      static BigInt generate_random_bigint(BigInt const &from, BigInt const &to);
      static BigInt find_primitive_root_for_prime(BigInt const &p);

      static bool primitiveRootExists(BigInt const &n);
      static BigInt findSmallestPrimitiveRoot(BigInt const &n);
      static std::vector<BigInt> getAllPrimitiveRoots(BigInt const &n);
      static std::vector<BigInt> getPrimeFactors(BigInt n);
      static bool isPrimitiveRoot(
            BigInt const &g,
            BigInt const &n,
            BigInt const &phi_n,
            std::vector<BigInt> const &factors);
      
};
#endif