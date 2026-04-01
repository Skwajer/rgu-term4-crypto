#include "VulnerableRsaKeyGenerator.hpp"
#include "../../math/Miller_Rabin_primality_test/MillerRabinPrimalityTest.hpp"

BigInt generate_random_in_range(const BigInt& min, const BigInt& max) 
{
    static boost::random::mt19937_64 rng(std::random_device{}());
    
    if (min > max) {
        throw std::invalid_argument("min must be <= max");
    }
    
    BigInt range = max - min + 1;
    size_t n_bits = boost::multiprecision::msb(range) + 1;
    
    BigInt result;
    
    do {
        result = 0;
        size_t words = (n_bits + 63) / 64;
        
        for (size_t i = 0; i < words; ++i) 
        {
            result <<= 64;
            result |= rng();
        }
        
        if (n_bits % 64 != 0) 
        {
            result &= (BigInt(1) << n_bits) - 1;
        }
        
        result += min;
        
    } while (result > max);
    
    return result;
}

BigInt VulnerableRsaKeyGenerator::generate_candidate(size_t bits)
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

BigInt VulnerableRsaKeyGenerator::generate_prime(size_t bits_count, double target_prob)
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

BigInt VulnerableRsaKeyGenerator::find_next_prime(BigInt prime, double target_prob)
{
    BigInt next_prime = prime + 2;
    auto primality_test = std::make_unique<MillerRabinPrimalityTest>();
    while (!(primality_test->is_prime(next_prime, target_prob)))
    {
        next_prime += 2;
    }
    return next_prime;
}

bool VulnerableRsaKeyGenerator::is_vulnerable_to_Wieners_attack(const BigInt& d, const BigInt& n)
{
    BigInt root4 = boost::multiprecision::sqrt(boost::multiprecision::sqrt(n));
    return d < (root4 / 3);
}

BigInt VulnerableRsaKeyGenerator::choose_public_exponent(const BigInt& phi_n)
{
    static const int exponents[] = {5, 3};

    for (int e_val : exponents)
    {
        BigInt e = e_val;

        if (NumberTheoryService::gcd(e, phi_n) == 1)
        {
            return e;
        }
    }

    throw std::runtime_error("Failed to find suitable public exponent");
}

rsaVulnerableKeys VulnerableRsaKeyGenerator::generate_vulnerable_to_Fermat_attack(size_t bits_count, double target_prob)
{
    BigInt p;
    BigInt q;
    BigInt n;
    BigInt phi_n;
    BigInt e, d;

    while (true)
    {
        p = generate_prime(bits_count / 2, target_prob);
        q = find_next_prime(p, target_prob);

        n = p * q;
        phi_n = (p - 1) * (q - 1);

        e = choose_public_exponent(phi_n);
        d = NumberTheoryService::get_inv(e, phi_n);

        if (is_vulnerable_to_Wieners_attack(d, n))
        {
            continue;
        }

        break;
    }

    return {{e, n}, {d, n}};
}

rsaVulnerableKeys VulnerableRsaKeyGenerator::generate_vulnerable_to_Wieners_attack(
    size_t bits_count, double target_prob)
{
    BigInt p;
    BigInt q;
    BigInt n;
    BigInt phi_n;
    BigInt e, d;
    
    
    while (true)
    {
        p = generate_prime(bits_count / 2, target_prob);
        q = generate_prime(bits_count / 2, target_prob);
        
        BigInt diff = p > q ? p - q : q - p;
        if (diff < (BigInt(1) << (bits_count / 4))) 
        {
            continue;
        }
        
        n = p * q;
        phi_n = (p - 1) * (q - 1);
        
        BigInt n_sqrt = boost::multiprecision::sqrt(n);
        BigInt n_quarter = boost::multiprecision::sqrt(n_sqrt);
        BigInt d_bound = n_quarter / 3;
        
        do 
        {
            d = generate_random_in_range(2, d_bound);
        } while (gcd(d, phi_n) != 1);
        
        e = NumberTheoryService::get_inv(d, phi_n);
        
        if (e < 2 || e >= phi_n) 
        {
            continue;
        }
        
        break;
    }
    
    return {{e, n}, {d, n}};
}