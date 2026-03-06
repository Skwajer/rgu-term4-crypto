#pragma once
#include "IFeistelRound.hpp"
#include "IKeyExpansion.hpp"
#include "namespaces_crypto.hpp"
#include <memory>
#include <vector>

namespace crypto 
{
    class FeistelNetwork 
    {
    private:
        std::unique_ptr<IFeistelRound> m_roundFunction;
        std::unique_ptr<IKeyExpansion> m_keyExpansion;
        size_t m_numRounds;
        std::vector<Bytes> m_round_keys;

    public:
        void set_round_keys(Bytes const &key);

        
    public:
        FeistelNetwork(std::unique_ptr<IFeistelRound> roundFunc,
                      std::unique_ptr<IKeyExpansion> keyExp,
                      size_t numRounds);
        
        Bytes encrypt(const Bytes& block);
        Bytes decrypt(const Bytes& block);
    };
}