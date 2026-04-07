#ifndef GF2N_HPP
#define GF2N_HPP
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <iostream>
#include <vector>

class GF2n final
{
    public:
    using u64 = uint64_t;

    public:
    GF2n(size_t init_n, u64 init_mod) : m_n(init_n), m_mod(init_mod)
    {
        if (m_n < 2 || m_n > 64)
        {
            throw std::invalid_argument("invalid n: must be in [2, 64]");
        }
    }

    std::string to_string(u64 elem)
    {
        std::string result;
        size_t i = 0;
        while (elem)
        {
            if (elem & 1)
            {
                if (i == 0)
                {
                    result += "1 ";
                }
                else if (i == 1) 
                {
                    result += "x ";
                }
                else 
                {
                    result += "x^" + std::to_string(i) + " ";
                }
                if (elem & (1 << 1)) {result += "+ ";}
            } else 
            {
                if ((elem & (1 << 1)) && (i != 0)) {result += "+ ";}
            }
            i++;
            elem >>= 1;
        }
        return result;
    }

    public:
    static u64 multi(u64 a, u64 b)
    {
        u64 result = 0;
        for (size_t i = 0; i < 32; i++)
        {
            if (b & (1 << i))
            {
                result ^= (a << i);
            }
        }
        return result;
    }

    inline u64 sum(u64 a, u64 b) const
    {
        return a ^ b;
    }

    u64 multi_mod(u64 a, u64 b) const
    {

        u64 result = 0;
        const u64 senior_bit = static_cast<u64>(1) << (m_n);
        while (b)
        {
            if (b & 1)
            {
                result ^= a;
            }
            b >>= 1;
            a <<= 1;
            if (a & senior_bit)
            {
                a ^= m_mod;
            }
        }
        return result;
    }

    static u64 multi_other_mod(u64 a, u64 b, u64 mod, size_t deg)
    {
        u64 result = 0;
        u64 senior_bit = static_cast<u64>(1) << deg;

        while (b)
        {
            if (b & 1)
            {
                result ^= a;
            }
            b >>= 1;
            a <<= 1;

            if (a & senior_bit)
            {
                a ^= mod;
            }
        }
        return result;
    }

    static int degree(u64 elem)
    {
        /** 
        * @return elem degree and -1 if elem is zero
        **/
        if (elem == 0) {return -1;}

        for (size_t i = 63; i > 0; i--)
        {
            if (elem & (static_cast<u64>(1) << i))
            {
                return i;
            }
        }
        return 0; // avoiding warning
    }

    static u64 div_mod(u64 a, u64 b, u64 &r)
    {
        u64 qt = 0;
        r = a;
        while (degree(r) >= degree(b))
        {
            u64 shift_diff = degree(r) - degree(b);
            qt |=  static_cast<u64>(1) << shift_diff;
            r ^= b << shift_diff;
        }
        return qt;
    }

    static u64 gcd(u64 a, u64 b)
    {
        u64 r;
        while (b != 0)
        {
            div_mod(a, b, r);
            a = b;
            b = r;
        }
        return a;
    }

    u64 egcd(u64 a, u64 b, u64 &s, u64 &t) const 
    {
        if ((a != 0) && (b == 0))
        {
            s = 1;
            t = 0;
            return a;
        }
        u64 old_s, old_t, r;
        u64 qt = div_mod(a, b, r);
        u64 gcd = egcd(b, r, old_s, old_t);
        s = old_t;
        t = old_s ^ multi(qt, old_t);
        return gcd;
    }

    u64 findInverse(u64 elem) const 
    {
        if (elem == 0)
        {
            return 0;
        }
        u64 x, y, mod = m_mod;
        u64 gcd = egcd(elem, mod, x, y);
        if (gcd != 1)
        {
            throw std::runtime_error("inverse not exist");
        }
        return x;
    }

    u64 pow_mod(u64 base, u64 exp) const
    {
        u64 result = 1;
        while (exp)
        {
            if (exp & 1)
            {
                result = multi_mod(result, base);
            }
            base = multi_mod(base, base);
            exp >>= 1;
        }
        return result;
    }

    static std::vector<size_t> factorize_degree(size_t n)
    {
        std::vector<size_t> factors;
        for (size_t p = 2; p * p <= n; p++)
        {
            if (n % p == 0)
            {
                factors.push_back(p);
                while (n % p == 0) n /= p;
            }
        }
        if (n > 1) factors.push_back(n);
        return factors;
    }

    bool is_irreducible(u64 f)
    {
        auto deg_f =  degree(f);
        u64 x = 2;
        u64 xp = x;
        for (int i = 0; i < deg_f; i ++)
        {
            xp = multi_other_mod(xp, xp, f, deg_f);
        }
        if (xp != x)
        {
            return false;
        }

        auto prime_factors = factorize_degree(deg_f);
        for (auto p : prime_factors)
        {
            size_t k = deg_f / p;

            u64 xp = x;
            for (size_t i = 0; i < k; i++)
            {
                xp = multi_other_mod(xp, xp, f, deg_f);
            }

            u64 g = gcd(f, xp ^ x);

            if (g != 1)
            {
                return false;
            }
        }

        return true;
    }


    private:
    u64 m_mod;    // poly for modular arithmetic
    size_t m_n;   // mod degree

};
#endif //GF2N_HPP