#ifndef IFEISTELROUND_HPP
#define IFEISTELROUND_HPP
#include "namespaces_crypto.hpp"

namespace crypto {
    class IFeistelRound {
    public:
        virtual ~IFeistelRound() = default;
        
        virtual Bytes encryptRound(const Bytes& block, const Bytes& roundKey) = 0;
    };
}
#endif //IFEISTELROUND_HPP