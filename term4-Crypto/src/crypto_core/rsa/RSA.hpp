#include "RsaKeyGeneration.hpp"
#include <vector>

using Bytes = std::vector<uint8_t>;

class RSA
{
public:
    static Bytes  encrypt(Bytes const &data, public_key const &pub_key);
    static Bytes decrypt(Bytes const &cipher, private_key const& priv_key);

    static BigInt bytes_to_bigint(Bytes const &data);
    static Bytes  bigint_to_bytes(BigInt value, size_t block_size);
};