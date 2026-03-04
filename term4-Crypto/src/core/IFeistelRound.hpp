#pragma once
#include "namespaces_crypto.hpp"

namespace crypto {
    class IFeistelRound {
    public:
        virtual ~IFeistelRound() = default;
        
        virtual Bytes encryptRound(const Bytes& block, const Bytes& roundKey) = 0;
    };
}