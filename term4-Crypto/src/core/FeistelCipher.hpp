#pragma once
#include "ISymmetricCipher.hpp"
#include "FeistelNetwork.hpp"
#include <memory>

namespace crypto 
{
    class FeistelCipher : public ISymmetricCipher 
    {
    protected:
        std::unique_ptr<FeistelNetwork> m_feistelNetwork;
        Bytes m_currentKey;
        
        virtual void preEncrypt(Bytes& block) = 0;
        virtual void postEncrypt(Bytes& block) = 0;
        //virtual void preDecrypt(Bytes& block) = 0;
        //virtual void postDecrypt(Bytes& block) = 0;
        
    public:
        FeistelCipher(std::unique_ptr<FeistelNetwork> network);
        virtual ~FeistelCipher() = default;
        
        void setKey(const Bytes& key) override;
        Bytes encryptBlock(const Bytes& block) override;
        Bytes decryptBlock(const Bytes& block) override;
    };
}