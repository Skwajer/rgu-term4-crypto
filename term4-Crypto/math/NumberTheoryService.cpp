#include "NumberTheoryService.hpp"
#include <boost/multiprecision/detail/default_ops.hpp>
#include <cstddef>
#include <stdexcept>
#include "Miller_Rabin_primality_test/MillerRabinPrimalityTest.hpp"
#include <random>
#include <memory>

BigInt NumberTheoryService::pow_mod(BigInt base, BigInt exp, BigInt mod)
{
    if (mod == 1) return 0;
    
    BigInt result = 1;
    base = base % mod;
    
    
    int iteration = 0;
    while (exp > 0) {
        iteration++;
        
        if (exp & 1) {
            result = (result * base) % mod;
        }
        
        exp >>= 1;
        
        if (exp > 0) { 
            base = (base * base) % mod;
        }
    }
    
    return result;
}

BigInt NumberTheoryService::computeLegendreSymbol(BigInt const &a, BigInt const &p)
{
    if (a % p == 0)
    {
        return 0;
    }
    BigInt result = pow_mod(a, (p - 1) / 2, p);
    if (result == 1)
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

BigInt NumberTheoryService::computeJacobiSymbol(BigInt a, BigInt n)
{
    if (n <= 0 || n % 2 == 0)
    {
        throw std::invalid_argument("n must be positive and odd");
    }

    if (gcd(a, n) != 1)
    {
        return 0;
    }

    BigInt result = 1;
    a = (a % n + n) % n;

    while (a != 0)
    {
        BigInt t = 0;

        while (a % 2 == 0)
        {
            a /= 2;
            t += 1;
        }

        if (t % 2 == 1)
        {
            BigInt b = n % 8;
            if (b == 3 || b == 5)
            {
                result = -result;
            }
        }

        if ((a % 4 == 3) && (n % 4 == 3))
        {
            result = -result;
        }

        std::swap(a, n);
        a %= n;
    }

    return result;
}

BigInt NumberTheoryService::gcd(BigInt a, BigInt b)
{
    if (b == 0)
    {
        return a;
    }
    return gcd(b, a % b);
}

BigInt NumberTheoryService::egcd(BigInt a, BigInt b, BigInt &x, BigInt &y)
{
    if (b == 0)
    {
        x = 1;
        y = 0;
        return a;
    }

    BigInt x1, y1;
    BigInt gcd = egcd(b, a % b, x1, y1);

    x = y1;
    y = x1 - (a / b) * y1;

    return gcd;
}

BigInt NumberTheoryService::get_inv(BigInt const &a, BigInt const &n)
{
    BigInt x, y;
    BigInt gcd = egcd(a, n,  x, y);
    if (gcd != 1)
    {
        throw std::runtime_error("inverse not exist");
    }
    return ((x % n) + n) % n;
}

BigInt NumberTheoryService::Euler_func_definition(BigInt const &n)
{
    BigInt result = 0;
    BigInt p_iter = n;
    while(p_iter)
    {
        if (gcd(n, p_iter) == 1)
        {
            result++;
        }
        p_iter--;
    }
    return result;
}

BigInt NumberTheoryService::Euler_func_factorization(BigInt const &n)
{
    BigInt result = n;
    BigInt n_iter = n;


    for(BigInt i = 2; i * i <= n_iter; i++)
    {
        if (n_iter % i == 0)
        {
            result /= i;
            result *= (i - 1);
            //result = result * (1 - 1 / i)
        }
        while (n_iter % i == 0) 
        {
            n_iter /= i;
        }
    }
    if (n_iter > 1)
    {
        result /= n_iter;
        result *= (n_iter - 1);
        //result  = result * (1 - 1 / n_iter)
    }

    return result;
}

BigInt NumberTheoryService::Euler_func_Fourier(BigInt const &n)
{
    if (n == 1)
    {
        return 1;
    }

    BigFloat result_sum = 0;
    for (BigInt k = 1; k < n; k++)
    {
        BigInt g = gcd(k, n);
        BigFloat exp_angle = 2 * M_PI * k.convert_to<BigFloat>() / n.convert_to<BigFloat>();
        result_sum += g.convert_to<BigFloat>() * cos(exp_angle);
    }
    return static_cast<BigInt>(round(result_sum));
}

BigInt NumberTheoryService::generate_candidate(size_t bits)
    {
        static boost::random::mt19937_64 rng(std::random_device{}());

        BigInt n = 0;

        size_t words = (bits + 63) / 64;

        for (size_t i = 0; i < words; ++i)
        {
            n <<= 64;
            n |= rng();
        }

        size_t extra_bits = words * 64 - bits;
        if (extra_bits > 0)
        {
            n >>= extra_bits;
        }

        n |= (BigInt(1) << (bits - 1));
        n |= 1;

        return n;
    }

    BigInt NumberTheoryService::generate_prime(size_t bits_count, double target_prob)
    {
        if (target_prob <= 0 || target_prob >= 1)
        {
            throw std::invalid_argument("the target probability should be in (0 ; 1)");
        }

        auto primality_test = std::make_unique<MillerRabinPrimalityTest>();

        BigInt p = generate_candidate(bits_count);

        while (!(primality_test->is_prime(p, target_prob)))
        {
            p += 2;

            if (boost::multiprecision::msb(p) + 1 > bits_count)
            {
                p = generate_candidate(bits_count);
            }
        }

        return p;
    }

    BigInt NumberTheoryService::generate_random_bigint(BigInt const &from,  BigInt const &to)
    {
        boost::random::mt19937 rng(std::random_device{}());
        boost::random::uniform_int_distribution<BigInt> dist(from, to);
        return dist(rng);
    }