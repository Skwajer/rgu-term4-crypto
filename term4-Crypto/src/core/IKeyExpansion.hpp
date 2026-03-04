#pragma once
#include "namespaces_crypto.hpp"
#include <vector>

namespace crypto {
    class IKeyExpansion {
    public:
        virtual ~IKeyExpansion() = default;
        
        virtual std::vector<Bytes> generateRoundKeys(const Bytes& key) = 0;
    };
}