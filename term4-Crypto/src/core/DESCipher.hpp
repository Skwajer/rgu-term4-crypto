#pragma once
#include "FeistelCipher.hpp"
#include "IKeyExpansion.hpp"
#include "IFeistelRound.hpp"
#include <cstdint>

namespace crypto {
    class DESCipher : public FeistelCipher {
    private:
        class DESKeyExpansion : public IKeyExpansion {
        private:
            static const std::vector<int> PC1;
            static const std::vector<int> PC2;
            static const std::vector<int> SHIFT_SCHEDULE;
            
        public:
            std::vector<uint64_t> generateRoundKeys(const std::vector<uint8_t>& key) override;
        };
        
        class DESRoundFunction : public IFeistelRound {
        private:
            static const std::vector<int> E;
            static const std::vector<std::vector<ByteArray>> S_BOXES;
            static const std::vector<int> P;
            
        public:
            uint32_t f(uint32_t R, uint64_t K);
            ByteArray encryptRound(const ByteArray& block, const ByteArray& roundKey) override {
                // Этот метод не используется - используем f напрямую
                return ByteArray();
            }
        };
        
        static const std::vector<int> IP;
        static const std::vector<int> FP;
        
        void preEncrypt(std::vector<uint8_t>& block) override;
        void postEncrypt(std::vector<uint8_t>& block) override;
        void preDecrypt(std::vector<uint8_t>& block) override;
        void postDecrypt(std::vector<uint8_t>& block) override;
        
        uint64_t permute(uint64_t block, const std::vector<int>& table);
        
    public:
        DESCipher();
    };
}