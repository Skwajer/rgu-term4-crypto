#ifndef NUMBER_THEORY_SERVICE_HPP
#define NUMBER_THEORY_SERVICE_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/fwd.hpp>

using BigInt = boost::multiprecision::int1024_t;
using BigFloat = boost::multiprecision::cpp_bin_float_100;

class NumberTheoryService
{
public:
      static BigInt computeLegendreSymbol(BigInt const &a, BigInt const &p);
      static BigInt computeJacobiSymbol(BigInt const &a, std::vector<BigInt> const &P_miltiplies);
      static BigInt gcd(BigInt a, BigInt b);
      static BigInt egcd(BigInt const &a, BigInt const &b, BigInt &x, BigInt &y);
      static BigInt pow_mod(BigInt a, BigInt degree, BigInt mod);
      static BigInt get_inv(BigInt const &a, BigInt const &n);
      static BigInt Euler_func_definition(BigInt const &p);
      static BigInt Euler_func_factorization(BigInt const &n);
      static BigInt Euler_func_Fourier(BigInt const &n);
      
};
#endif