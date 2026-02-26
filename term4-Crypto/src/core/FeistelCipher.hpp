#pragma once
#include "ISymmetricCipher.hpp"
#include "FeistelNetwork.hpp"
#include <memory>

namespace crypto {
    class FeistelCipher : public ISymmetricCipher {
    protected:
        std::unique_ptr<FeistelNetwork> m_feistelNetwork;
        ByteArray m_currentKey;
        
        virtual void preEncrypt(ByteArray& block) = 0;
        virtual void postEncrypt(ByteArray& block) = 0;
        virtual void preDecrypt(ByteArray& block) = 0;
        virtual void postDecrypt(ByteArray& block) = 0;
        
    public:
        FeistelCipher(std::unique_ptr<FeistelNetwork> network);
        virtual ~FeistelCipher() = default;
        
        void setKey(const ByteArray& key) override;
        ByteArray encryptBlock(const ByteArray& block) override;
        ByteArray decryptBlock(const ByteArray& block) override;
    };
}