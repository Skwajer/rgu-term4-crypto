#include "RSA.hpp"
#include "RsaKeyGeneration.hpp"
#include <boost/multiprecision/integer.hpp>
#include <stdexcept>
#include <iostream>
Bytes RSA::encrypt(Bytes const &data, public_key const &pub_key)
{
    BigInt m = bytes_to_bigint(data);
    std::cout << "m = " << m << std::endl;
    if (m >= pub_key.N)
        throw std::invalid_argument("plain text too large");

    BigInt c = NumberTheoryService::pow_mod(m, pub_key.e, pub_key.N);
    size_t n_bytes = (boost::multiprecision::msb(pub_key.N) + 1 + 7) / 8;
    return bigint_to_bytes(c, n_bytes);
}

Bytes RSA::decrypt(Bytes const &cipher, const private_key& priv_key)
{
    BigInt c = bytes_to_bigint(cipher);
    BigInt m = NumberTheoryService::pow_mod(c, priv_key.d, priv_key.N);
    size_t n_bytes = (boost::multiprecision::msb(priv_key.N) + 1 + 7) / 8;

    return bigint_to_bytes(m, n_bytes);
}

BigInt RSA::bytes_to_bigint(const Bytes &data)
{
    BigInt result = 0;
    for (uint8_t byte : data)
    {
        result <<= 8;
        result |= byte;
    }
    return result;
}

Bytes RSA::bigint_to_bytes(BigInt value, size_t size)
{
    
    Bytes result(size, 0);

    for (size_t i = size; i > 0; --i)
    {
        result[i - 1] = static_cast<uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return result;
}