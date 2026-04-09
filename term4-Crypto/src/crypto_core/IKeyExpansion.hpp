#ifndef IKEYEXPANSION_HPP
#define IKEYEXPANSION_HPP 
#include "namespaces_crypto.hpp"
#include <vector>

namespace crypto {
    class IKeyExpansion {
    public:
        virtual ~IKeyExpansion() = default;
        
        virtual std::vector<Bytes> generateRoundKeys(const Bytes& key) = 0;
    };
}
#endif //IKEYEXPANSION_HPP