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

    void add_to_block(Bytes& block, uint64_t delta) {
      uint64_t carry = delta;
      for (size_t i = 0; i < block.size() && carry != 0; ++i) {
        uint16_t sum = static_cast<uint16_t>(block[i]) + static_cast<uint16_t>(carry & 0xFF);
        block[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = (carry >> 8) + (sum >> 8);
      }
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

Bytes validated_iv(const Bytes& iv, size_t bs,
                             const char* mode_name) 
{
      if (iv.empty()) return Bytes(bs, 0x00);
      if (iv.size() != bs)
        throw std::invalid_argument(std::string(mode_name) +
          ": IV size does not match block size");
      return iv;
}

CFB::CFB(Bytes iv) : m_iv(std::move(iv)) {}

  Bytes CFB::get_iv(size_t bs) const {
    return validated_iv(m_iv, bs, "CFB");
  }

  void CFB::encrypt(ISymmetricCipher& cipher, const Bytes& input,
                    Bytes& output, size_t) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("CFB: input not block-aligned");

    Bytes iv = get_iv(bs);
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) 
    {
      Bytes plain(input.begin() + b * bs, input.begin() + (b + 1) * bs);
      Bytes enc = xor_blocks(cipher.encryptBlock(iv), plain);
      std::copy(enc.begin(), enc.end(), output.begin() + b * bs);
      iv = enc;
    }
  }

  void CFB::decrypt(ISymmetricCipher& cipher, const Bytes& input,
                    Bytes& output, size_t) 
{
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("CFB: input not block-aligned");

    Bytes iv = get_iv(bs);
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    for (size_t b = 0; b < n_blocks; ++b) 
    {
        Bytes cipher_block(input.begin() + b * bs,
                                input.begin() + (b + 1) * bs);
        Bytes plain = xor_blocks(cipher.encryptBlock(iv), cipher_block);
        std::copy(plain.begin(), plain.end(), output.begin() + b * bs);
        iv = cipher_block;
    }
}


OFB::OFB(Bytes iv) : m_iv(std::move(iv)) {}

  Bytes OFB::get_iv(size_t bs) const 
{
    return validated_iv(m_iv, bs, "OFB");
}

  void OFB::process(ISymmetricCipher& cipher, const Bytes& iv,
                    const Bytes& input, Bytes& output) 
{
    const size_t bs = cipher.block_size();
    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    Bytes keystream = iv;
    for (size_t b = 0; b < n_blocks; ++b) 
    {
        keystream = cipher.encryptBlock(keystream);
        Bytes plain(input.begin() + b * bs, input.begin() + (b + 1) * bs);
        Bytes out_block = xor_blocks(plain, keystream);
        std::copy(out_block.begin(), out_block.end(), output.begin() + b * bs);
    }
  }

  void OFB::encrypt(ISymmetricCipher& cipher, const Bytes& input,
                    Bytes& output, size_t) 
{
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("OFB: input not block-aligned");
    process(cipher, get_iv(bs), input, output);
}

  void OFB::decrypt(ISymmetricCipher& cipher, const Bytes& input,
                    Bytes& output, size_t) 
{
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("OFB: input not block-aligned");
    process(cipher, get_iv(bs), input, output);
}


CTR::CTR(Bytes nonce) : m_nonce(std::move(nonce)) {}

  Bytes CTR::make_counter_block(const Bytes& nonce,
                                      uint64_t counter, size_t bs) {
    if (nonce.size() != 0 && nonce.size() != bs - 8)
      throw std::invalid_argument(
        "CTR: nonce size must be 0 or (block_size - 8)");

    Bytes block(bs, 0x00);

    if (!nonce.empty())
      std::copy(nonce.begin(), nonce.end(), block.begin());

    for (int i = 7; i >= 0; --i) {
      block[bs - 8 + i] = static_cast<uint8_t>(counter & 0xFF);
      counter >>= 8;
    }
    return block;
  }

  void CTR::process(ISymmetricCipher& cipher, const Bytes& input,
                    Bytes& output, size_t threads) {
    const size_t bs = cipher.block_size();
    if (input.size() % bs != 0)
      throw std::invalid_argument("CTR: input not block-aligned");

    const size_t n_blocks = input.size() / bs;
    output.resize(input.size());

    auto ranges = split_blocks_between_threads(n_blocks, threads);
    std::vector<std::thread> workers;
    workers.reserve(ranges.size());

    for (auto [start, end] : ranges) 
    {
      workers.emplace_back([&, start, end]() 
      {
        for (size_t b = start; b < end; ++b) {
          Bytes counter_block = make_counter_block(m_nonce, b, bs);
          Bytes keystream = cipher.encryptBlock(counter_block);
          Bytes plain(input.begin() + b * bs,
                            input.begin() + (b + 1) * bs);
          Bytes out_block = xor_blocks(plain, keystream);
          std::copy(out_block.begin(), out_block.end(),
                    output.begin() + b * bs);
        }
      });
    }
    for (auto& w : workers) w.join();
  }

  void CTR::encrypt(ISymmetricCipher& cipher, const Bytes& input,
                    Bytes& output, size_t threads) 
{
    process(cipher, input, output, threads);
}

  void CTR::decrypt(ISymmetricCipher& cipher, const Bytes& input,
                    Bytes& output, size_t threads) 
{
    process(cipher, input, output, threads);
}


  RD::RD(uint64_t seed) : m_seed(seed) {}

  void RD::encrypt(ISymmetricCipher& cipher,
                   const Bytes& input,
                   Bytes& output,
                   size_t) {
    const size_t bs = cipher.block_size();

    if (input.size() % bs != 0)
      throw std::invalid_argument("RandomDelta: input not block-aligned");

    const size_t n_blocks = input.size() / bs;

    std::mt19937_64 rng(m_seed != 0
                          ? m_seed
                          : static_cast<uint64_t>(std::random_device{}()));

    Bytes initial(bs);
    for (auto& byte : initial)
      byte = static_cast<uint8_t>(rng() & 0xFF);

    const uint64_t delta = rng();

    Bytes delta_block(bs, 0);
    for (size_t i = 0; i < 8 && i < bs; ++i)
      delta_block[i] = static_cast<uint8_t>((delta >> (i * 8)) & 0xFF);

    output.resize((n_blocks + 2) * bs);

    Bytes enc_initial = cipher.encryptBlock(initial);
    std::copy(enc_initial.begin(), enc_initial.end(), output.begin());

    Bytes enc_delta = cipher.encryptBlock(delta_block);
    std::copy(enc_delta.begin(), enc_delta.end(), output.begin() + bs);

    Bytes counter = initial;
    for (size_t b = 0; b < n_blocks; ++b) 
    {
      add_to_block(counter, delta);

      Bytes plain(input.begin() + b * bs, input.begin() + (b + 1) * bs);
      Bytes masked = xor_blocks(plain, counter);
      Bytes enc = cipher.encryptBlock(masked);

      std::copy(enc.begin(), enc.end(), output.begin() + (b + 2) * bs);
    }
  }

  void RD::decrypt(ISymmetricCipher& cipher,
                   const Bytes& input,
                   Bytes& output,
                   size_t) {
    const size_t bs = cipher.block_size();

    if (input.size() < 3 * bs || input.size() % bs != 0)
      throw std::invalid_argument("RandomDelta: invalid ciphertext size");

    const size_t n_blocks = input.size() / bs - 2;
    output.resize(n_blocks * bs);

    Bytes enc_initial(input.begin(), input.begin() + bs);
    Bytes initial = cipher.decryptBlock(enc_initial);

    Bytes enc_delta(input.begin() + bs, input.begin() + 2 * bs);
    Bytes delta_block = cipher.decryptBlock(enc_delta);

    uint64_t delta = 0;
    for (size_t i = 0; i < 8 && i < bs; ++i)
      delta |= static_cast<uint64_t>(delta_block[i]) << (i * 8);

    Bytes counter = initial;
    for (size_t b = 0; b < n_blocks; ++b) {
      add_to_block(counter, delta);

      Bytes enc_block(input.begin() + (b + 2) * bs,
                            input.begin() + (b + 3) * bs);
      Bytes masked = cipher.decryptBlock(enc_block);
      Bytes plain = xor_blocks(masked, counter);

      std::copy(plain.begin(), plain.end(), output.begin() + b * bs);
    }
  }





}

