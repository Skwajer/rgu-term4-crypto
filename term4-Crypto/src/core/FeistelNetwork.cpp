#include "FeistelNetwork.hpp"
#include <stdexcept>
#include <cstdint>
#include <cstring>

namespace crypto {
    FeistelNetwork::FeistelNetwork(std::unique_ptr<IFeistelRound> roundFunc,
                                   std::unique_ptr<IKeyExpansion> keyExp,
                                   size_t numRounds)
        : m_roundFunction(std::move(roundFunc))
        , m_keyExpansion(std::move(keyExp))
        , m_numRounds(numRounds) {
        if (!m_roundFunction || !m_keyExpansion) {
            throw std::invalid_argument("Round function and key expansion must be provided");
        }
    }
    
    ByteArray FeistelNetwork::encrypt(const ByteArray& block, const ByteArray& key) {
        if (block.size() != 8) {
            throw std::invalid_argument("Block size must be 8 bytes for DES");
        }
        
        auto roundKeys = m_keyExpansion->generateRoundKeys(key);
        if (roundKeys.size() < m_numRounds) {
            throw std::runtime_error("Insufficient round keys generated");
        }
        
        uint32_t left = 0, right = 0;
        
        for (int i = 0; i < 4; i++) {
            left = (left << 8) | block[i];
        }
        for (int i = 4; i < 8; i++) {
            right = (right << 8) | block[i];
        }
        
        for (size_t round = 0; round < m_numRounds; round++) {
            uint32_t newRight = left ^ ((DESRoundFunction*)m_roundFunction.get())->f(right, roundKeys[round]);
            left = right;
            right = newRight;
        }
        
        ByteArray result(8);
        
        for (int i = 3; i >= 0; i--) {
            result[i] = right & 0xFF;
            right >>= 8;
        }
        for (int i = 7; i >= 4; i--) {
            result[i] = left & 0xFF;
            left >>= 8;
        }
        
        return result;
    }
    
    ByteArray FeistelNetwork::decrypt(const ByteArray& block, const ByteArray& key) {
        if (block.size() != 8) {
            throw std::invalid_argument("Block size must be 8 bytes for DES");
        }
        
        auto roundKeys = m_keyExpansion->generateRoundKeys(key);
        if (roundKeys.size() < m_numRounds) {
            throw std::runtime_error("Insufficient round keys generated");
        }
        
        uint32_t left = 0, right = 0;
        
        for (int i = 0; i < 4; i++) {
            left = (left << 8) | block[i];
        }
        for (int i = 4; i < 8; i++) {
            right = (right << 8) | block[i];
        }
        
        for (int round = m_numRounds - 1; round >= 0; round--) {
            uint32_t newLeft = right ^ ((DESRoundFunction*)m_roundFunction.get())->f(left, roundKeys[round]);
            right = left;
            left = newLeft;
        }
        
        ByteArray result(8);
        
        for (int i = 3; i >= 0; i--) {
            result[i] = left & 0xFF;
            left >>= 8;
        }
        for (int i = 7; i >= 4; i--) {
            result[i] = right & 0xFF;
            right >>= 8;
        }
        
        return result;
    }
}