#include "CipherContext.hpp"
#include <future>
#include <memory>
#include <stdexcept>


namespace crypto
{

    CipherContext::CipherContext(std::unique_ptr<ISymmetricCipher> cipher,
         CipherMd cipher_mode, PaddingMode padding, Bytes init_vector, ...)
    {
        m_cipher = std::move(cipher);
        configure_cipher_mode(cipher_mode);
        configure_padding(padding);
        m_init_vector = init_vector;
    }

    void CipherContext::encrypt(Bytes const &text, Bytes &result, size_t threads)
    {
        auto block_size = m_cipher->block_size();
        auto padded = m_padding->apply(text, block_size);
        m_cipher_mode->decrypt(*m_cipher, padded, result, threads);
    }

    void CipherContext::decrypt(Bytes const &cipher, Bytes &result, size_t threads)
    {
        auto block_size = m_cipher->block_size();
        m_cipher_mode->decrypt(*m_cipher, cipher, result, threads);
        result = m_padding->remove(result, block_size);
    }


    std::future<void> CipherContext::encrypt_file(std::string const &in_path, std::string const &out_path, size_t threads)
    {
        return std::async(std::launch::async, [this, in_path, out_path, threads] ()
        {
            process_file(in_path, out_path, threads, true);
        });
    }

    std::future<void> CipherContext::decrypt_file(std::string const &in_path, std::string const &out_path, size_t threads)
    {
        return std::async(std::launch::async, [this, in_path, out_path, threads] ()
        {
            process_file(in_path, out_path, threads, false);
        });
    }

    void CipherContext::process_file(std::string const &in_path, std::string const &out_path, size_t threads, bool encrypt)
    {
        std::ifstream inputFile(in_path, std::ios::binary);
        if (!inputFile) {
            throw std::runtime_error("cannot open input file: " + in_path);
        }
        
        std::ofstream outputFile(out_path, std::ios::binary);
        if (!outputFile) {
            throw std::runtime_error("cannot create output file: " + out_path);
        }
        
        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(inputFile)),
                                     std::istreambuf_iterator<char>());
        
        std::vector<uint8_t> result;
        auto block_size = m_cipher->block_size();
        if (encrypt) 
        {
            auto padded = m_padding->apply(buffer, block_size);
            m_cipher_mode->encrypt(*m_cipher, padded, result, threads);
        } else 
        {
            m_cipher_mode->decrypt(*m_cipher, buffer, result, threads);
            result = m_padding->remove(result, block_size);
        }
    
        outputFile.write(reinterpret_cast<const char*>(result.data()), result.size());
    }

    void CipherContext::configure_cipher_mode(CipherMd cipher_mode)
    {
        switch (cipher_mode) 
        {
            case ECB_md:
            {
                m_cipher_mode = std::make_unique<ECB>();
                break;
            }

            case CBC_md:
            {
                m_cipher_mode = std::make_unique<CBC>();
                break;
            }

            case PCBC_md:
            {
                m_cipher_mode = std::make_unique<PCBC>();
                break;
            }
            
            default:
            {
                throw std::invalid_argument("incorrect cipher mode");
            }
        }
    }

    void CipherContext::configure_padding(PaddingMode padding)
    {
        switch (padding) 
        {
         case Zeros:
         {
            m_padding = std::make_unique<ZerosPadding>();
            break;
         }

         case ANSIX923:
         {
            m_padding = std::make_unique<AnsiX923Padding>();
            break;
         }
         
         default:
         {
            throw std::invalid_argument("incorrect paddind mode");
         }
        }
    }
}