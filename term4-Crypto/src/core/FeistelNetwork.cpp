#include "FeistelNetwork.hpp"
#include "namespaces_crypto.hpp"
#include <algorithm>
#include <stdexcept>
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

    void FeistelNetwork::set_round_keys(Bytes const &key)
    {
        m_round_keys = m_keyExpansion->generateRoundKeys(key);
    }
    
    Bytes FeistelNetwork::encrypt(const Bytes& block)
    {
        Bytes b = block;

        if (m_round_keys.size() < m_numRounds) 
        {
            printf("%llu\n", m_round_keys.size());
            throw std::runtime_error("Insufficient round keys generated");
        }
        
        size_t half_part_size = (b.size() / 2); 
        Bytes L(b.begin(), b.begin() + half_part_size);
        Bytes R(b.begin() + half_part_size, b.end());
        
        for (size_t round = 0; round < m_numRounds; round++) 
        {
            auto FR = m_roundFunction->encryptRound(R, m_round_keys[round]);

            auto old_L = L;
            L = R;
            Bytes new_R(half_part_size);
            for (auto i = 0; i < L.size(); i++)
            {
                new_R[i] = old_L[i] ^ FR[i];
            }
            R = std::move(new_R);
        }
        Bytes result;
        result.reserve(b.size());
        result.insert(result.end(), R.begin(), R.end());
        result.insert(result.end(), L.begin(), L.end());

        return result;
    }
    
    Bytes FeistelNetwork::decrypt(const Bytes& block) 
    {
        Bytes b = block;

        if (m_round_keys.size() < m_numRounds) 
        {
            throw std::runtime_error("Insufficient round keys generated");
        }
        
        size_t half_part_size = (b.size() / 2); 
        Bytes L(b.begin(), b.begin() + half_part_size);
        Bytes R(b.begin() + half_part_size, b.end());
        auto reversed_round_keys = m_round_keys;
        std::reverse(reversed_round_keys.begin(), reversed_round_keys.end());
        
        for (size_t round = 0; round < m_numRounds; round++) 
        {
            auto FR = m_roundFunction->encryptRound(R, reversed_round_keys[round]);

            auto old_L = L;
            L = R;
            Bytes new_R(half_part_size);
            for (auto i = 0; i < L.size(); i++)
            {
                new_R[i] = old_L[i] ^ FR[i];
            }
            R = std::move(new_R);
        }
        Bytes result;
        result.reserve(b.size());
        result.insert(result.end(), R.begin(), R.end());
        result.insert(result.end(), L.begin(), L.end());

        return result;
    }
}