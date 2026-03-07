#include "modes.hpp"
#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace crypto 
{

    static std::vector<std::pair<size_t, size_t>> split_blocks_between_threads(size_t total_blocks, size_t total_threads)
    {
        std::vector<std::pair<size_t, size_t>> result;
        result.reserve(total_threads);
        auto blocks_per_thread = total_blocks / total_threads;
        auto remaining_blocks = total_blocks % total_threads;

        size_t current_block = 0;
        for (auto t = 0; t < total_threads; t++)
        {
            auto blocks_of_current_thread = blocks_per_thread + (t < remaining_blocks ? 1 : 0);

            auto start = current_block;
            auto end = current_block + blocks_of_current_thread;
            current_block = end;
            result.push_back({start, end});
        }
        return result;
    }

    static Bytes xor_blocks(Bytes const &a, Bytes const &b)
    {
        if (a.size() != b.size()) {throw std::invalid_argument("blocks size must be equal");}
        Bytes result(a.size());
        for (size_t i = 0; i < a.size(); i++)
        {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }


    // ===== ECB =====
void ECB::process(ISymmetricCipher &cipher, const Bytes &input,
                    Bytes &output, size_t threads, bool encrypting)
{
    auto block_size = cipher.block_size();
    auto total_input_bytes = input.size();
    if (total_input_bytes % block_size != 0)
    {
        throw std::invalid_argument("ECB: input data must be padded to cipher block size");
    }
    auto total_blocks = total_input_bytes / block_size;
    output.clear();
    output.resize(input.size());
    
    auto threads_ranges = split_blocks_between_threads(total_blocks, threads);
    std::vector<std::thread> workers;

    for (auto [start, end] : threads_ranges)
    {
        workers.emplace_back([&, start, end] ()
        {
            for (auto current_block = start; current_block < end; current_block++)
            {
                Bytes block(input.begin() + current_block*block_size, input.begin() + current_block*block_size + block_size);
                Bytes result = (encrypting ? cipher.encryptBlock(block) : cipher.decryptBlock(block));
                std::copy(result.begin(), result.end(), output.begin() + current_block * block_size);
            }
        });
    }

    for (auto &t : workers)
    {
        t.join();
    }
}


void ECB::encrypt(ISymmetricCipher &cipher, const Bytes &input,
            Bytes &output, size_t threads)
{
    process(cipher, input, output, threads, true);   
}

void ECB::decrypt(ISymmetricCipher &cipher, const Bytes &input,
            Bytes &output, size_t threads)
{
    process(cipher, input, output, threads, false);

}



    // ===== CBC =====

CBC::CBC(Bytes iv)
{
    m_iv = std::move(iv);
}

void CBC::validate_iv(size_t block_size) const
{
    if (m_iv.empty())
    {
        throw std::invalid_argument("init_vector cannot be empty");
    }
    if ((m_iv.size() % block_size) != 0)
    {
        throw  std::invalid_argument("init_vector cannot be empty or multiple of block");
    }
}

void CBC::encrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads)
{
    auto block_size = cipher.block_size();
    auto total_input_bytes = input.size();
    if (total_input_bytes % block_size != 0)
    {
        throw std::invalid_argument("CBC: input data must be padded to cipher block size");
    }
    auto total_blocks = total_input_bytes / block_size;
    output.clear();
    output.resize(input.size());

    validate_iv(block_size);
    Bytes first_block(input.begin(), input.begin() + block_size);

    auto current_encrypted = cipher.encryptBlock(xor_blocks(first_block, m_iv));
    std::copy(current_encrypted.begin(), current_encrypted.end(), output.begin());

    for (size_t b = 1; b < total_blocks; b++)
    {
        Bytes current_block(input.begin() + b*block_size, input.begin() + b*block_size + block_size);
        current_encrypted = cipher.encryptBlock(xor_blocks(current_block, current_encrypted));
        std::copy(current_encrypted.begin(), current_encrypted.end(), output.begin() + b * block_size);
    }
}

void CBC::decrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads)
{
    auto block_size = cipher.block_size();
    auto total_input_bytes = input.size();
    if (total_input_bytes % block_size != 0) 
    {
        throw std::invalid_argument("CBC: input data must be padded to cipher block size");
    }
    auto total_blocks = total_input_bytes / block_size;
    validate_iv(block_size);
    output.clear();
    output.resize(input.size());
    auto threads_ranges = split_blocks_between_threads(total_blocks - 1, threads);
    std::vector<std::thread> workers;

    Bytes first_cipherBlock(input.begin(), input.begin() + block_size);
    
    auto first_decrypted = xor_blocks(cipher.decryptBlock(first_cipherBlock), m_iv);
    std::copy(first_decrypted.begin(), first_decrypted.end(), output.begin());

    for (auto [start, end] : threads_ranges)
    {
        workers.emplace_back([&, start, end] ()
        {
            for (auto relative_block = start; relative_block < end; relative_block++)
            {
                auto current_block = relative_block + 1;
                size_t prev_cipherBlock_id = current_block - 1;
                Bytes prev_cipherBlock(input.begin() + prev_cipherBlock_id*block_size, input.begin() + block_size * (prev_cipherBlock_id + 1));
                Bytes block(input.begin() + current_block*block_size, input.begin() + current_block*block_size + block_size);
                Bytes result = xor_blocks(cipher.decryptBlock(block), prev_cipherBlock);
                std::copy(result.begin(), result.end(), output.begin() + current_block * block_size);
            }
        });
    }

    for (auto &t : workers)
    {
        t.join();
    }
}


    // ===== PCBC =====

void PCBC::validate_iv(size_t bs) const
{
    if (m_iv.empty() || ((m_iv.size() % bs) != 0))
    {
        throw std::invalid_argument("init_vector cannot be empty or multiple of block");
    }
}

PCBC::PCBC(Bytes iv)
{
    m_iv = std::move(iv);
}

void PCBC::encrypt(ISymmetricCipher& cipher, const Bytes& input,
                     Bytes& output, size_t threads) 
{
    const size_t block_size = cipher.block_size();
    if (input.size() % block_size != 0) 
    {
      throw std::invalid_argument("PCBC: input data must be padded to cipher block size");
    }
    validate_iv(block_size);
    auto prev_contibution = m_iv;
    const size_t n_blocks = input.size() / block_size;
    output.clear();
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) 
    {
      Bytes plain(input.begin() + b * block_size, input.begin() + (b + 1) * block_size);
      Bytes enc = cipher.encryptBlock(xor_blocks(plain, prev_contibution));
      std::copy(enc.begin(), enc.end(), output.begin() + b * block_size);
      prev_contibution = xor_blocks(plain, enc);
    }
}

void PCBC::decrypt(ISymmetricCipher& cipher, const Bytes& input,
                     Bytes& output, size_t) 
{
    const size_t block_size = cipher.block_size();
    if (input.size() % block_size != 0)
      throw std::invalid_argument("PCBC: input not block-aligned");

    validate_iv(block_size);
    auto prev_contibution = m_iv;
    const size_t n_blocks = input.size() / block_size;
    output.clear();
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) 
    {
      Bytes cipher_block(input.begin() + b * block_size,
                               input.begin() + (b + 1) * block_size);
      Bytes plain = xor_blocks(cipher.decryptBlock(cipher_block), prev_contibution);
      std::copy(plain.begin(), plain.end(), output.begin() + b * block_size);
      prev_contibution = xor_blocks(plain, cipher_block);
    }
}
}

