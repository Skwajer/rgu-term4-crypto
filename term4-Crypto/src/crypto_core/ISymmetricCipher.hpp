#pragma once
#include "namespaces_crypto.hpp"

namespace crypto {
    class ISymmetricCipher {
    public:
        virtual ~ISymmetricCipher() = default;
        
        virtual void setKey(const Bytes& key) = 0;
        
        virtual Bytes encryptBlock(const Bytes& block) = 0;
        
        virtual Bytes decryptBlock(const Bytes& block) = 0;

        virtual size_t block_size() const = 0;
    };
}