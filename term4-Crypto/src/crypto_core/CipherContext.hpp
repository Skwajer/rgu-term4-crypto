#include <memory>
#include <vector>
#include "ISymmetricCipher.hpp"
#include "../mode/cipher_mode.hpp"
#include "namespaces_crypto.hpp"
#include "../padding/padding.hpp"

namespace crypto {

enum CipherMd
{
    ECB,
    CBC,
    PCBC
};

enum PaddingMode
{
    Zeros,
    ANSIX923
};

class CipherContext
{
public:
    CipherContext(std::unique_ptr<crypto::ISymmetricCipher> cipher, CipherMd cipher_mode, PaddingMode padding, Bytes init_vector, ...);
    
    void encrypt(Bytes const &text, Bytes &result, size_t threads);
    void decrypt(Bytes const &cipher, Bytes &result, size_t threads);

private:
    std::unique_ptr<IPadding> m_padding;
    std::unique_ptr<CipherMode> m_cipher_mode;
};
}