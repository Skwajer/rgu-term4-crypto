#pragma once
#include "../crypto_core/FeistelCipher.hpp"
#include "../crypto_core/IKeyExpansion.hpp"
#include "../crypto_core/IFeistelRound.hpp"
#include "../crypto_core/namespaces_crypto.hpp"
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

        size_t block_size() const override;
                
    public:
        DESCipher();
    };
}