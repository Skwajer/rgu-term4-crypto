#pragma once
#include "../crypto_core/namespaces_crypto.hpp"
#include "../crypto_core/ISymmetricCipher.hpp"
#include <cstddef>
#include <vector>

namespace crypto 
{
    class RijndaelCipher : public ISymmetricCipher 
    {
    public:
        std::vector<Bytes> generateRoundKeys(const Bytes& key);
        Bytes encryptBlock(const Bytes& block) override;
        Bytes decryptBlock(const Bytes& block) override;

        size_t block_size() const override;
                
    public:
        RijndaelCipher(size_t block_bits = 128, size_t key_bits = 128);

    private:
        // size in bytes
        size_t m_block_size;
        size_t m_key_size;
        size_t m_rounds;
        std::vector<Bytes> m_round_keys;
    };
}