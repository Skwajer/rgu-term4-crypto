#include "RijndaelCipher.hpp"
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace crypto 
{
    RijndaelCipher::RijndaelCipher(GF2n::u64 gf8_mod, size_t block_bits, size_t key_bits) : m_gf8(GF2n::degree(gf8_mod), gf8_mod)
    {
        if (!GF2n::is_irreducible(gf8_mod))
        {
            throw std::runtime_error("it is impossible to create a Galua field based on this polynomial");
        }
        if (block_bits != 128 && block_bits != 192 && block_bits != 256)
        {
            throw std::invalid_argument("The algorithm supports block lengths of 128 bit, 192 bit, and 256 bit");
        }
        if (key_bits != 128 && key_bits != 192 && key_bits != 256)
        {
            throw std::invalid_argument("Key lengths supported by the algorithm: 128 bit, 192 bit, 256 bit.");
        }
        m_block_size = block_bits / 8;
        m_key_size = key_bits / 8;

        if (key_bits == 128) {m_rounds = 10;}
        else if (key_bits == 192) {m_rounds = 12;}
        else {m_rounds = 14;}
    }

    void RijndaelCipher::setKey(const Bytes& key)
    {
        generateRoundKeys(key);
    }

    size_t RijndaelCipher::block_size() const
    {
        return m_block_size;
    }

    Byte RijndaelCipher::affineTransform(GF2n::u64 b)
    {
        unsigned char result = 0;
        unsigned char c = 99;
        for (int i = 0; i < 8; i++)
        {
            unsigned char bit = (b >> i) & 1;
            bit ^= (b >> ((i + 4) % 8)) & 1;
            bit ^= (b >> ((i + 5) % 8)) & 1;
            bit ^= (b >> ((i + 6) % 8)) & 1;
            bit ^= (b >> ((i + 7) % 8)) & 1;
            bit ^= (c >> i) & 1;
            result |= (bit << i);
        }
        return result;
    }

    void RijndaelCipher::calculate_s_box(GF2n::u64 f)
    {
        for (GF2n::u64 i = 0; i < 256; i++)
        {
            GF2n::u64 inverted = m_gf8.findInverse(i);
            m_s_box[i] = affineTransform(inverted);
        }

        for (int i = 0; i < 256; i++)
        {
            m_inv_s_box[m_s_box[i]] = i;
        }
    }

    void RijndaelCipher::SubBytes(std::vector<Byte> &state)
    {
        for (int i = 0; i < state.size(); i++)
        {
            state[i] = m_s_box[state[i]];
        }
    }

    void RijndaelCipher::ShiftRows(std::vector<Byte> &state)
    {
        std::vector<Byte> result(state.size());
        auto Nb = m_block_size / 4;
        int shifts[4];
        if (Nb == 8)
        {
            shifts[0] = 0;
            shifts[1] = 1;
            shifts[2] = 3;
            shifts[3] = 4;
        }
        else 
        {
            shifts[0] = 0;
            shifts[1] = 1;
            shifts[2] = 2;
            shifts[3] = 3;
        }

        for (size_t row = 0; row < 4; row++)
        {
            for (size_t col = 0; col < Nb; col++)
            {
                size_t src_index = row*Nb + col;
                size_t dest_col = (src_index - shifts[row]) % Nb;
                size_t dest_index = row * Nb + dest_col;
                result[dest_index] = state[src_index];
            }
        }
        state = result;
    }

    void RijndaelCipher::MixColumns(std::vector<Byte> &state)
    {
        
        auto Nb = m_block_size / 4;
        std::vector<Byte> result(state.size());
        
        for (size_t col = 0; col < Nb; col++)
        {
            Byte a0 = state[0 * Nb + col];
            Byte a1 = state[1 * Nb + col];
            Byte a2 = state[2 * Nb + col];
            Byte a3 = state[3 * Nb + col];
            
            Byte mul_02_00 = m_gf8.multi_mod(a0, 0x02);
            Byte mul_02_01 = m_gf8.multi_mod(a1, 0x02);
            Byte mul_02_02 = m_gf8.multi_mod(a2, 0x02);
            Byte mul_02_03 = m_gf8.multi_mod(a3, 0x02);
            
            Byte mul_03_00 = m_gf8.multi_mod(a0, 0x03);
            Byte mul_03_01 = m_gf8.multi_mod(a1, 0x03);
            Byte mul_03_02 = m_gf8.multi_mod(a2, 0x03);
            Byte mul_03_03 = m_gf8.multi_mod(a3, 0x03);
            
            // b0 = {02}·a0 ⊕ {03}·a1 ⊕ a2 ⊕ a3
            Byte b0 = mul_02_00 ^ mul_03_01 ^ a2 ^ a3;
            
            // b1 = a0 ⊕ {02}·a1 ⊕ {03}·a2 ⊕ a3
            Byte b1 = a0 ^ mul_02_01 ^ mul_03_02 ^ a3;
            
            // b2 = a0 ⊕ a1 ⊕ {02}·a2 ⊕ {03}·a3
            Byte b2 = a0 ^ a1 ^ mul_02_02 ^ mul_03_03;
            
            // b3 = {03}·a0 ⊕ a1 ⊕ a2 ⊕ {02}·a3
            Byte b3 = mul_03_00 ^ a1 ^ a2 ^ mul_02_03;
            
            result[0 * Nb + col] = b0;
            result[1 * Nb + col] = b1;
            result[2 * Nb + col] = b2;
            result[3 * Nb + col] = b3;
        }
        state = result;
    }

    void RijndaelCipher::InvMixColumns(std::vector<Byte> &state)
    {    
        auto Nb = m_block_size / 4;
        std::vector<Byte> result(state.size());
        
        // {0E}, {0B}, {0D}, {09}
        for (size_t col = 0; col < Nb; col++)
        {
            Byte a0 = state[0 * Nb + col];
            Byte a1 = state[1 * Nb + col];
            Byte a2 = state[2 * Nb + col];
            Byte a3 = state[3 * Nb + col];
            
            Byte mul_0e_00 = m_gf8.multi_mod(a0, 0x0E);
            Byte mul_0b_01 = m_gf8.multi_mod(a1, 0x0B);
            Byte mul_0d_02 = m_gf8.multi_mod(a2, 0x0D);
            Byte mul_09_03 = m_gf8.multi_mod(a3, 0x09);
            
            Byte mul_09_00 = m_gf8.multi_mod(a0, 0x09);
            Byte mul_0e_01 = m_gf8.multi_mod(a1, 0x0E);
            Byte mul_0b_02 = m_gf8.multi_mod(a2, 0x0B);
            Byte mul_0d_03 = m_gf8.multi_mod(a3, 0x0D);
            
            Byte mul_0d_00 = m_gf8.multi_mod(a0, 0x0D);
            Byte mul_09_01 = m_gf8.multi_mod(a1, 0x09);
            Byte mul_0e_02 = m_gf8.multi_mod(a2, 0x0E);
            Byte mul_0b_03 = m_gf8.multi_mod(a3, 0x0B);
            
            Byte mul_0b_00 = m_gf8.multi_mod(a0, 0x0B);
            Byte mul_0d_01 = m_gf8.multi_mod(a1, 0x0D);
            Byte mul_09_02 = m_gf8.multi_mod(a2, 0x09);
            Byte mul_0e_03 = m_gf8.multi_mod(a3, 0x0E);
            
            Byte b0 = mul_0e_00 ^ mul_0b_01 ^ mul_0d_02 ^ mul_09_03;
            Byte b1 = mul_09_00 ^ mul_0e_01 ^ mul_0b_02 ^ mul_0d_03;
            Byte b2 = mul_0d_00 ^ mul_09_01 ^ mul_0e_02 ^ mul_0b_03;
            Byte b3 = mul_0b_00 ^ mul_0d_01 ^ mul_09_02 ^ mul_0e_03;
            
            result[0 * Nb + col] = b0;
            result[1 * Nb + col] = b1;
            result[2 * Nb + col] = b2;
            result[3 * Nb + col] = b3;
        }
        
        state = result;
    }

    void RijndaelCipher::AddRoundKey(std::vector<Byte> &state, size_t round)
    {
        auto Nb = m_block_size / 4;
        size_t offset = round * Nb;
        
        for (size_t col = 0; col < Nb; col++) 
        {
            uint32_t round_key_word = m_w[offset + col];
            state[col * 4 + 0] ^= (round_key_word >> 24) & 0xFF;
            state[col * 4 + 1] ^= (round_key_word >> 16) & 0xFF;
            state[col * 4 + 2] ^= (round_key_word >> 8) & 0xFF;
            state[col * 4 + 3] ^= round_key_word & 0xFF;
        }
    }

    uint32_t RijndaelCipher::SubWord(uint32_t word)
    {
        uint32_t result = 0;
        
        for (int i = 0; i < 4; i++)
        {
            uint8_t byte = (word >> (24 - 8*i)) & 0xFF;
            
            uint8_t substituted = m_s_box[byte];
            
            result |= (static_cast<uint32_t>(substituted) << (24 - 8*i));
        }
        
        return result;
    }

    uint32_t RijndaelCipher::RotWord(uint32_t word)
    {
        return (word << 8) | (word >> 24);
    }

    uint32_t RijndaelCipher::Rcon(size_t i)
{
    static const uint32_t rcon[] = 
    {
        0x01000000,  // 1: 2^0
        0x02000000,  // 2: 2^1
        0x04000000,  // 3: 2^2
        0x08000000,  // 4: 2^3
        0x10000000,  // 5: 2^4
        0x20000000,  // 6: 2^5
        0x40000000,  // 7: 2^6
        0x80000000,  // 8: 2^7
        0x1B000000,  // 9: 2^8 
        0x36000000,  // 10: 2^9
        0x6C000000,  // 11: 2^10
        0xD8000000,  // 12: 2^11
        0xAB000000,  // 13: 2^12
        0x4D000000,  // 14: 2^13
        0x9A000000   // 15: 2^14
    };
    
    const size_t max_rcon = sizeof(rcon) / sizeof(rcon[0]);
    
    if (i < 1 || i > max_rcon) 
    {
        throw std::out_of_range("Rcon index out of range");
    }

    return rcon[i - 1];
}

    void RijndaelCipher::generateRoundKeys(Bytes const &key)
    {
        size_t Nb = m_block_size / 4;
        size_t Nk = m_key_size / 4;
        m_w.clear();
        m_w.reserve(Nb * (m_rounds + 1));
        for (size_t i = 0; i < Nk; i++)
        {
            uint32_t word = (key[4*i] << 24) | (key[4*i + 1] << 16) | (key[4*i + 2] << 8) | (key[4*i + 3]);
            m_w.push_back(word);
        }


        for (size_t i = Nk; i < Nb * (m_rounds + 1); i++)
        {
            uint32_t temp = m_w[i - 1];
            if (i % Nk == 0)
            {
                temp = SubWord(RotWord(temp)) ^ Rcon(i / Nk);
            }
            else if (Nk > 6 && (i % Nk == 4))
            {
                temp = SubWord(temp);
            }
            m_w[i] = m_w[i - Nk] ^ temp;
        }
    }

    Bytes RijndaelCipher::encryptBlock(const Bytes& block)
    {
        if (block.size() != m_block_size) 
        {
            throw std::runtime_error("Block size mismatch");
        }
        
        size_t Nb = m_block_size / 4;
        std::vector<Byte> state(m_block_size);
        for (size_t col = 0; col < Nb; col++) 
        {
            for (size_t row = 0; row < 4; row++) 
            {
                state[row * Nb + col] = block[col * 4 + row];
            }
        }
        
        AddRoundKey(state, 0);
        
        for (size_t round = 1; round < m_rounds; round++) 
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, round);
        }
        
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, m_rounds);
        
        Bytes result(m_block_size);
        for (size_t col = 0; col < Nb; col++) 
        {
            for (size_t row = 0; row < 4; row++) 
            {
                result[col * 4 + row] = state[row * Nb + col];
            }
        }
        
        return result;
    }

    Bytes RijndaelCipher::decryptBlock(const Bytes& block)
    {
        if (block.size() != m_block_size) 
        {
            throw std::runtime_error("Block size mismatch");
        }
        
        size_t Nb = m_block_size / 4;
        std::vector<Byte> state(m_block_size);
        
        for (size_t col = 0; col < Nb; col++) 
        {
            for (size_t row = 0; row < 4; row++) 
            {
                state[row * Nb + col] = block[col * 4 + row];
            }
        }
        
        AddRoundKey(state, m_rounds);
        
        for (size_t round = m_rounds - 1; round >= 1; round--) 
        {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, round);
            InvMixColumns(state);
        }
        
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, 0);
        
        Bytes result(m_block_size);
        for (size_t col = 0; col < Nb; col++) 
        {
            for (size_t row = 0; row < 4; row++) 
            {
                result[col * 4 + row] = state[row * Nb + col];
            }
        }
        
        return result;
    }
}