#include <fstream>
#include <future>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include "ISymmetricCipher.hpp"
#include "../mode/modes.hpp"
#include "namespaces_crypto.hpp"
#include "../padding/padding.hpp"

namespace crypto {

enum CipherMd
{
    ECB_md,
    CBC_md,
    PCBC_md
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
    
    void encrypt(Bytes const &text, Bytes &result, size_t threads = 1);
    void decrypt(Bytes const &cipher, Bytes &result, size_t threads = 1);

    std::future<void> encrypt_file(std::string const &in_path, std::string const &out_path, size_t threads = 1);
    std::future<void> decrypt_file(std::string const &in_path, std::string const &out_path, size_t threads = 1);

    void configure_cipher_mode(CipherMd cipher_mode);
    void configure_padding(PaddingMode padding);

    void process_file(std::string const &in_path, std::string const &out_path, size_t threads, bool encrypt);

private:
    std::unique_ptr<ISymmetricCipher> m_cipher;
    std::unique_ptr<IPadding> m_padding;
    std::unique_ptr<CipherMode> m_cipher_mode;
    Bytes m_init_vector;
    // std::mt19937 m_rng;
};
}