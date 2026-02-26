#pragma once
#include "namespaces_crypto.hpp"

namespace crypto {
    class IFeistelRound {
    public:
        virtual ~IFeistelRound() = default;
        
        // Шифрующее преобразование раунда сети Фейстеля
        virtual ByteArray encryptRound(const ByteArray& block, const ByteArray& roundKey) = 0;
    };
}