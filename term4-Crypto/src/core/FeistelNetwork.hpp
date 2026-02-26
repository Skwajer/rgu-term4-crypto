#pragma once
#include "IFeistelRound.hpp"
#include "IKeyExpansion.hpp"
#include <memory>

namespace crypto {
    class FeistelNetwork {
    private:
        std::unique_ptr<IFeistelRound> m_roundFunction;
        std::unique_ptr<IKeyExpansion> m_keyExpansion;
        size_t m_numRounds;
        
    public:
        FeistelNetwork(std::unique_ptr<IFeistelRound> roundFunc,
                      std::unique_ptr<IKeyExpansion> keyExp,
                      size_t numRounds);
        
        ByteArray encrypt(const ByteArray& block, const ByteArray& key);
        ByteArray decrypt(const ByteArray& block, const ByteArray& key);
    };
}