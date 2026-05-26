#pragma once
#include "DESCipher.hpp"
#include "../crypto_core/ISymmetricCipher.hpp"

namespace crypto {
    class TripleDESCipher : public ISymmetricCipher
    {
    public:
        enum Mode
        {
            EEE3,
            EDE3,
            EEE2,
            EDE2,
        };

    public:
        explicit TripleDESCipher(Mode mode = EEE3) : m_mode(mode)
        {}

        void setKey(const Bytes& key) override;

        Bytes encryptBlock(const Bytes& block) override;
        Bytes decryptBlock(const Bytes& block) override;

        size_t block_size() const override;

    private:
        DESCipher m_des1;
        DESCipher m_des2;
        DESCipher m_des3;

        Mode m_mode;
    };
}