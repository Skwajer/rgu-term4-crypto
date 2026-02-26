#pragma once
#include "namespaces_crypto.hpp"
#include <vector>

namespace crypto {
    class IKeyExpansion {
    public:
        virtual ~IKeyExpansion() = default;
        
        // Генерация раундовых ключей из входного ключа
        virtual std::vector<ByteArray> generateRoundKeys(const ByteArray& key) = 0;
    };
}