#include "NumberTheoryService.hpp"
#include <cstddef>

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

BigInt NumberTheoryService::computeJacobiSymbol(BigInt const &a, std::vector<BigInt> const &P_miltiplies)
{
    BigInt result = 1;
    for (size_t i = 0; i < P_miltiplies.size(); i++)
    {
        result *= a / P_miltiplies[i];
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

BigInt NumberTheoryService::egcd(BigInt const &a, BigInt const &b, BigInt &x, BigInt &y)
{
    if (b == 0)
    {
        x = 1;
        y = 0;
        return a;
    }
    BigInt gcd = egcd(b, a % b, x, y);
    BigInt x_prev = x;
    x = y;
    y = x_prev - (a/b) * y;
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
    return x;
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