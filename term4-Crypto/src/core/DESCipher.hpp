#pragma once
#include "FeistelCipher.hpp"
#include "IKeyExpansion.hpp"
#include "IFeistelRound.hpp"
#include "namespaces_crypto.hpp"
#include <cstdint>

namespace crypto {
    class DESCipher : public FeistelCipher {
    public:
        class DESKeyExpansion : public IKeyExpansion 
        { 
        public:
            std::vector<Bytes> generateRoundKeys(const Bytes& key) override;
        };
        
        class DESRoundFunction : public IFeistelRound 
        {   
        public:
            Bytes encryptRound(const Bytes& block, const Bytes& roundKey) override;
        };
        
        void preEncrypt(std::vector<uint8_t>& block) override;
        void postEncrypt(std::vector<uint8_t>& block) override;

                
    public:
        DESCipher();
    };
}