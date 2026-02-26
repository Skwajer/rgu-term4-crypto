#pragma once
#include "namespaces_crypto.hpp"

namespace crypto {
    class ISymmetricCipher {
    public:
        virtual ~ISymmetricCipher() = default;
        
        // Установка ключа шифрования/дешифрования
        virtual void setKey(const ByteArray& key) = 0;
        
        // Шифрование блока данных
        virtual ByteArray encryptBlock(const ByteArray& block) = 0;
        
        // Дешифрование блока данных
        virtual ByteArray decryptBlock(const ByteArray& block) = 0;
    };
}