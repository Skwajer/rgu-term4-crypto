#include "RabinCryptosystem.hpp"

#include <algorithm>
#include <stdexcept>

RabinCryptosystem::RabinCryptosystem()
    : B(0)
{
}

BigInt RabinCryptosystem::generate_blum_prime(
    size_t bits_count,
    double target_prob
)
{
    while (true)
    {
        BigInt prime =
            NumberTheoryService::generate_prime(bits_count, target_prob);

        if (prime % 4 == 3)
        {
            return prime;
        }
    }
}

BigInt RabinCryptosystem::bytes_to_bigint(
    const std::vector<uint8_t>& bytes
)
{
    BigInt result = 0;

    for (uint8_t byte : bytes)
    {
        result = (result << 8) | byte;
    }

    return result;
}

std::vector<uint8_t> RabinCryptosystem::bigint_to_bytes(
    const BigInt& num,
    size_t min_size
)
{
    std::vector<uint8_t> bytes;

    BigInt temp = num;

    if (temp == 0)
    {
        bytes.push_back(0);
    }
    else
    {
        while (temp > 0)
        {
            bytes.push_back(
                static_cast<uint8_t>(temp & 0xFF)
            );

            temp >>= 8;
        }

        std::reverse(bytes.begin(), bytes.end());
    }

    if (bytes.size() < min_size)
    {
        std::vector<uint8_t> padded(
            min_size - bytes.size(),
            0
        );

        padded.insert(
            padded.end(),
            bytes.begin(),
            bytes.end()
        );

        return padded;
    }

    return bytes;
}

size_t RabinCryptosystem::bigint_byte_size(const BigInt& num)
{
    if (num == 0)
    {
        return 1;
    }

    BigInt temp = num;

    size_t bits = 0;

    while (temp > 0)
    {
        ++bits;
        temp >>= 1;
    }

    return (bits + 7) / 8;
}

BigInt RabinCryptosystem::sqrt_mod_blum_prime(
    const BigInt& a,
    const BigInt& p
)
{
    return NumberTheoryService::pow_mod(
        a,
        (p + 1) / 4,
        p
    );
}

BigInt RabinCryptosystem::crt(
    const BigInt& a1,
    const BigInt& a2,
    const BigInt& m1,
    const BigInt& m2
)
{
    BigInt M = m1 * m2;

    BigInt M1 = M / m1;
    BigInt M2 = M / m2;

    BigInt inv1 =
        NumberTheoryService::get_inv(M1 % m1, m1);

    BigInt inv2 =
        NumberTheoryService::get_inv(M2 % m2, m2);

    BigInt result =
        (a1 * M1 * inv1 + a2 * M2 * inv2) % M;

    if (result < 0)
    {
        result += M;
    }

    return result;
}

void RabinCryptosystem::generateKeys(
    size_t bits_count,
    double target_prob
)
{
    p = generate_blum_prime(bits_count, target_prob);

    do
    {
        q = generate_blum_prime(bits_count, target_prob);
    }
    while (p == q);

    n = p * q;

    do
    {
        B = NumberTheoryService::generate_random_bigint(
            1,
            n - 1
        );
    }
    while (NumberTheoryService::gcd(B, n) != 1);
}

void RabinCryptosystem::setKeys(
    const BigInt& p_key,
    const BigInt& q_key,
    const BigInt& n_key,
    const BigInt& B_key
)
{
    p = p_key;
    q = q_key;
    n = n_key;

    if (p % 4 != 3 || q % 4 != 3)
    {
        throw std::invalid_argument(
            "p and q must satisfy p ≡ q ≡ 3 mod 4"
        );
    }

    if (n != p * q)
    {
        throw std::invalid_argument(
            "n must equal p*q"
        );
    }

    if (B_key != 0)
    {
        if (NumberTheoryService::gcd(B_key, n) != 1)
        {
            throw std::invalid_argument(
                "gcd(B, n) must equal 1"
            );
        }

        B = B_key;
    }
    else
    {
        do
        {
            B = NumberTheoryService::generate_random_bigint(
                1,
                n - 1
            );
        }
        while (NumberTheoryService::gcd(B, n) != 1);
    }
}

std::vector<uint8_t> RabinCryptosystem::encrypt(
    const std::vector<uint8_t>& plaintext
)
{
    std::vector<uint8_t> ciphertext;

    size_t n_byte_size = bigint_byte_size(n);

    constexpr size_t overhead = 2;

    if (n_byte_size <= overhead + 1)
    {
        throw std::runtime_error(
            "Key size too small"
        );
    }

    size_t max_data_per_block =
        n_byte_size - overhead - 1;

    uint32_t original_size =
        static_cast<uint32_t>(plaintext.size());

    ciphertext.push_back((original_size >> 24) & 0xFF);
    ciphertext.push_back((original_size >> 16) & 0xFF);
    ciphertext.push_back((original_size >> 8) & 0xFF);
    ciphertext.push_back(original_size & 0xFF);

    for (size_t i = 0;
         i < plaintext.size();
         i += max_data_per_block)
    {
        size_t current_size =
            std::min(
                max_data_per_block,
                plaintext.size() - i
            );

        std::vector<uint8_t> block;

        block.push_back(PREFIX_MARKER);

        block.push_back(
            static_cast<uint8_t>(current_size)
        );

        block.insert(
            block.end(),
            plaintext.begin() + i,
            plaintext.begin() + i + current_size
        );

        while (block.size() < n_byte_size - 1)
        {
            block.push_back(
                static_cast<uint8_t>(
                    NumberTheoryService::generate_random_bigint(0, 255)
                )
            );
        }

        BigInt m = bytes_to_bigint(block);

        while (m >= n)
        {
            block.pop_back();

            block.push_back(
                static_cast<uint8_t>(
                    NumberTheoryService::generate_random_bigint(0, 255)
                )
            );

            m = bytes_to_bigint(block);
        }

        BigInt c =
            (m * (m + B)) % n;

        std::vector<uint8_t> enc =
            bigint_to_bytes(c, n_byte_size);

        ciphertext.insert(
            ciphertext.end(),
            enc.begin(),
            enc.end()
        );
    }

    return ciphertext;
}

std::vector<uint8_t> RabinCryptosystem::decrypt(
    const std::vector<uint8_t>& ciphertext
)
{
    if (ciphertext.size() < 4)
    {
        throw std::runtime_error(
            "Invalid ciphertext"
        );
    }

    uint32_t original_size =
        (static_cast<uint32_t>(ciphertext[0]) << 24) |
        (static_cast<uint32_t>(ciphertext[1]) << 16) |
        (static_cast<uint32_t>(ciphertext[2]) << 8) |
        static_cast<uint32_t>(ciphertext[3]);

    size_t n_byte_size = bigint_byte_size(n);

    if ((ciphertext.size() - 4) % n_byte_size != 0)
    {
        throw std::runtime_error(
            "Invalid ciphertext size"
        );
    }

    size_t num_blocks =
        (ciphertext.size() - 4) / n_byte_size;

    BigInt inv2 =
        NumberTheoryService::get_inv(2, n);

    std::vector<uint8_t> plaintext;

    size_t pos = 4;

    for (size_t block_index = 0;
         block_index < num_blocks;
         ++block_index)
    {
        std::vector<uint8_t> enc_block(
            ciphertext.begin() + pos,
            ciphertext.begin() + pos + n_byte_size
        );

        pos += n_byte_size;

        BigInt c = bytes_to_bigint(enc_block);

        BigInt D =
            (B * B + 4 * c) % n;

        BigInt sqrt_p =
            sqrt_mod_blum_prime(D % p, p);

        BigInt sqrt_q =
            sqrt_mod_blum_prime(D % q, q);

        std::vector<BigInt> roots =
        {
            crt(sqrt_p, sqrt_q, p, q),
            crt(sqrt_p, q - sqrt_q, p, q),
            crt(p - sqrt_p, sqrt_q, p, q),
            crt(p - sqrt_p, q - sqrt_q, p, q)
        };

        bool found = false;

        for (const BigInt& root : roots)
        {
            BigInt m =
                ((root - B) * inv2) % n;

            if (m < 0)
            {
                m += n;
            }

            BigInt check =
                (m * (m + B)) % n;

            if (check != c)
            {
                continue;
            }

            std::vector<uint8_t> bytes =
                bigint_to_bytes(
                    m,
                    n_byte_size - 1
                );

            if (bytes.size() < 2)
            {
                continue;
            }

            if (bytes[0] != PREFIX_MARKER)
            {
                continue;
            }

            uint8_t data_size = bytes[1];

            if (data_size > bytes.size() - 2)
            {
                continue;
            }

            plaintext.insert(
                plaintext.end(),
                bytes.begin() + 2,
                bytes.begin() + 2 + data_size
            );

            found = true;
            break;
        }

        if (!found)
        {
            throw std::runtime_error(
                "Failed to decrypt block " +
                std::to_string(block_index)
            );
        }
    }

    if (plaintext.size() > original_size)
    {
        plaintext.resize(original_size);
    }

    return plaintext;
}

BigInt RabinCryptosystem::getPublicKey() const
{
    return n;
}

BigInt RabinCryptosystem::getPrivateKeyP() const
{
    return p;
}

BigInt RabinCryptosystem::getPrivateKeyQ() const
{
    return q;
}

BigInt RabinCryptosystem::getB() const
{
    return B;
}