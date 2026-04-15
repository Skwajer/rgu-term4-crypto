#include "TwoFishCipher.hpp"
#include "../../math/GF2n/gf2n.hpp"
#include <cstddef>
#include <stdexcept>
#include <vector>
#include <cstdint>

const uint8_t Q0[256] = {
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
  };

  const uint8_t Q1[256] = {
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
  };

  const uint8_t MDS[4][4] = {
    {0x01, 0xEF, 0x5B, 0x5B},
    {0x5B, 0xEF, 0xEF, 0x01},
    {0xEF, 0x5B, 0x01, 0xEF},
    {0xEF, 0x01, 0xEF, 0x5B}
  };

  const uint8_t RS[4][8] = {
    {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
    {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
    {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
    {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}
  };

namespace crypto 
{
    TwofishCipher::TwofishCipher()
    {
        
    }

    uint32_t TwofishCipher::rol32(uint32_t x, int n) 
    {
        return (x << n) | (x >> (32 - n));
    }

    uint32_t TwofishCipher::ror32(uint32_t x, int n) 
    {
        return (x >> n) | (x << (32 - n));
    }
    size_t TwofishCipher::block_size() const
    {
        return 16;
    }

    void TwofishCipher::setKey(Bytes const &key)
    {
        if (key.size() > 32)
        {
            throw std::invalid_argument("key must be less than 256 bits");
        }
        m_key_size = key.size();
        KeySchedule(key);
    }

    void TwofishCipher::KeySchedule(Bytes const &key)
    {
        size_t must_be_padded_to = 32;
        if ((m_key_size != 32) && (m_key_size != 24) && (m_key_size != 16))
        {
            if (m_key_size < 24)
            {
                must_be_padded_to = (m_key_size < 16? 16 : 24);
            }
        }
        Bytes padded_key(must_be_padded_to, 0);
        for (size_t i = 0; i < m_key_size; i++)
        {
            padded_key[i] = key[i];
        }
        size_t k = m_key_size / 8;

        std::vector<uint32_t> Me(k), Mo(k), S(k);

        for (size_t i = 0; i < 2*k; i++)
        {
            uint32_t word = 0;
            for (size_t j = 0; j < 4; j++)
            {
                word |= (uint32_t)padded_key[4*i + j] << (8 * j);
            }
            if (i & 1)
                Mo[i/2] = word;
            else 
                Me[i/2] = word;
        }
        GF2n Gf(8, 0x14D);
        for (size_t i = 0; i < k; i++)
        {
            uint8_t input[8];
            for (size_t j = 0; j < 8; j++)
            {
                input[j] = padded_key[8*i + j];
            }
            uint8_t output[4] = {0};
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 8; col++)
                {
                    output[row] ^= Gf.multi_mod(RS[row][col], input[col]);
                }
            }

            uint32_t s_word = (output[3] << 24) | (output[2] << 16) | (output[1] << 8) | output[0];

            S[k - 1 - i] = s_word;
        }

        for (int i = 0; i < 20; i++) 
        {
            uint32_t A = h_func(2 * i * 0x01010101, Me, k);
            uint32_t B = h_func((2 * i + 1) * 0x01010101, Mo, k);
            
            B = (B << 8) | (B >> 24);
            
            m_subkeys[2 * i]     = A + B;
            m_subkeys[2 * i + 1] = (A + 2 * B) << 9;
        }

        for (int b = 0; b < 256; b++) 
        {
            uint32_t X = (b << 24) | (b << 16) | (b << 8) | b;
            uint32_t result = h_func(X, S, k);
            
            m_sboxs[0][b] = (result >> 0) & 0xFF;
            m_sboxs[1][b] = (result >> 8) & 0xFF;
            m_sboxs[2][b] = (result >> 16) & 0xFF;
            m_sboxs[3][b] = (result >> 24) & 0xFF;
        }
    }

    uint32_t TwofishCipher::h_func(uint32_t x, const std::vector<uint32_t>& L, size_t k)
    {
        auto b0 = (uint8_t)(x);
        auto b1 = (uint8_t)(x >> 8);
        auto b2 = (uint8_t)(x >> 16);
        auto b3 = (uint8_t)(x >> 24);

        if (k == 4) {
            b0 = Q1[b0] ^ (uint8_t)(L[3]);
            b1 = Q0[b1] ^ (uint8_t)(L[3] >> 8);
            b2 = Q0[b2] ^ (uint8_t)(L[3] >> 16);
            b3 = Q1[b3] ^ (uint8_t)(L[3] >> 24);
            
            b0 = Q1[b0] ^ (uint8_t)(L[2]);
            b1 = Q1[b1] ^ (uint8_t)(L[2] >> 8);
            b2 = Q0[b2] ^ (uint8_t)(L[2] >> 16);
            b3 = Q0[b3] ^ (uint8_t)(L[2] >> 24);
            
            b0 = Q0[Q1[b0] ^ (uint8_t)(L[1])] ^ (uint8_t)(L[0]);
            b1 = Q0[Q0[b1] ^ (uint8_t)(L[1] >> 8)] ^ (uint8_t)(L[0] >> 8);
            b2 = Q1[Q1[b2] ^ (uint8_t)(L[1] >> 16)] ^ (uint8_t)(L[0] >> 16);
            b3 = Q1[Q0[b3] ^ (uint8_t)(L[1] >> 24)] ^ (uint8_t)(L[0] >> 24);
        }
        else if (k == 3) {
            b0 = Q1[b0] ^ (uint8_t)(L[2]);
            b1 = Q0[b1] ^ (uint8_t)(L[2] >> 8);
            b2 = Q0[b2] ^ (uint8_t)(L[2] >> 16);
            b3 = Q1[b3] ^ (uint8_t)(L[2] >> 24);
            
            b0 = Q0[Q1[b0] ^ (uint8_t)(L[1])] ^ (uint8_t)(L[0]);
            b1 = Q0[Q0[b1] ^ (uint8_t)(L[1] >> 8)] ^ (uint8_t)(L[0] >> 8);
            b2 = Q1[Q1[b2] ^ (uint8_t)(L[1] >> 16)] ^ (uint8_t)(L[0] >> 16);
            b3 = Q1[Q0[b3] ^ (uint8_t)(L[1] >> 24)] ^ (uint8_t)(L[0] >> 24);
        }
        else { // k == 2
            b0 = Q0[Q1[b0] ^ (uint8_t)(L[1])] ^ (uint8_t)(L[0]);
            b1 = Q0[Q0[b1] ^ (uint8_t)(L[1] >> 8)] ^ (uint8_t)(L[0] >> 8);
            b2 = Q1[Q1[b2] ^ (uint8_t)(L[1] >> 16)] ^ (uint8_t)(L[0] >> 16);
            b3 = Q1[Q0[b3] ^ (uint8_t)(L[1] >> 24)] ^ (uint8_t)(L[0] >> 24);
        }

        GF2n Gf(8, 0x14D);
        uint8_t y[4] = {b0, b1, b2, b3};
        uint8_t output[4] = {0};
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i] ^= Gf.multi_mod(MDS[i][j], y[j]);
            }
        }
        
        return (output[3] << 24) | (output[2] << 16) | (output[1] << 8) | output[0];
    }

    uint32_t TwofishCipher::g_func(uint32_t X)
    {
        uint8_t x[4];
        for (size_t i = 0; i < 4; i++)
        {
            x[i] = X >> (8*i) & 0xFF;
        }
        uint8_t y[4];
        for (size_t i = 0; i < 4; i++)
        {
            y[i] = m_sboxs[i][x[i]];
        }
        GF2n Gf(8, 0x14D);
        uint8_t output[4] = {0};
        for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    output[row] ^= Gf.multi_mod(MDS[row][col], y[col]);
                }
            }
        return (output[3] << 24) | (output[2] << 16) | 
           (output[1] << 8) | output[0];
    }

    Bytes TwofishCipher::encryptBlock(Bytes const &block)
    {
        if (block.size() != BLOCK_SIZE)
        {
            throw std::invalid_argument("block size in TwoFish cipher must be 128 bits");
        }
        uint32_t A = block[0] | (block[1] << 8) | (block[2] << 16) | (block[3] << 24);
        uint32_t B = block[4] | (block[5] << 8) | (block[6] << 16) | (block[7] << 24);
        uint32_t C = block[8] | (block[9] << 8) | (block[10] << 16) | (block[11] << 24);
        uint32_t D = block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24);
        A = A ^ m_subkeys[0];
        B = B ^ m_subkeys[1];
        C = C ^ m_subkeys[2];
        D = D ^ m_subkeys[3];

        for (size_t round = 0; round < ROUNDS_COUNT; round++)
        {
            uint32_t L1 = g_func(A);
            uint32_t L2 = g_func(rol32((B), 8));
            uint32_t R1 = (L1 + L2 + m_subkeys[2*round + 8]) & 0xFFFFFFFFu;
            uint32_t R2 = (L1 + 2*L2 + m_subkeys[2*round + 9]) & 0xFFFFFFFFu;
            C = ror32((C ^ R1), 1);
            D = rol32(D, 1) ^ R2;
            
            if (round != ROUNDS_COUNT - 1)
            {
                uint32_t temp = A;
                A = C;
                C = temp;   
                temp = B;
                B = D;      
                D = temp; 
            }
        }
        A = A ^ m_subkeys[4];
        B = B ^ m_subkeys[5];
        C = C ^ m_subkeys[6];
        D = D ^ m_subkeys[7];

        Bytes result(BLOCK_SIZE);
        result[0] = (uint8_t)(A);
        result[1] = (uint8_t)(A >> 8);
        result[2] = (uint8_t)(A >> 16);
        result[3] = (uint8_t)(A >> 24);
        result[4] = (uint8_t)(B);
        result[5] = (uint8_t)(B >> 8);
        result[6] = (uint8_t)(B >> 16);
        result[7] = (uint8_t)(B >> 24);
        result[8] = (uint8_t)(C);
        result[9] = (uint8_t)(C >> 8);
        result[10] = (uint8_t)(C >> 16);
        result[11] = (uint8_t)(C >> 24);
        result[12] = (uint8_t)(D);
        result[13] = (uint8_t)(D >> 8);
        result[14] = (uint8_t)(D >> 16);
        result[15] = (uint8_t)(D >> 24);

        return result;
    }

    Bytes TwofishCipher::decryptBlock(Bytes const &block)
    {
        if (block.size() != BLOCK_SIZE) {
        throw std::invalid_argument("Twofish: block must be 16 bytes");
        }

        uint32_t A = (uint32_t)block[0] | ((uint32_t)block[1] << 8) | ((uint32_t)block[2] << 16) | ((uint32_t)block[3] <<
        24);
        uint32_t B = (uint32_t)block[4] | ((uint32_t)block[5] << 8) | ((uint32_t)block[6] << 16) | ((uint32_t)block[7] <<
        24);
        uint32_t C = (uint32_t)block[8] | ((uint32_t)block[9] << 8) | ((uint32_t)block[10] << 16) | ((uint32_t)block[11] <<
        24);
        uint32_t D = (uint32_t)block[12] | ((uint32_t)block[13] << 8) | ((uint32_t)block[14] << 16) | ((uint32_t)block[15]
        << 24);

        A ^= m_subkeys[4];
        B ^= m_subkeys[5];
        C ^= m_subkeys[6];
        D ^= m_subkeys[7];

        for (int r = ROUNDS_COUNT - 1; r >= 0; r--) 
        {
        if (r != ROUNDS_COUNT - 1)
        {
            uint32_t tmp = A;
            A = C;
            C = tmp;
            tmp = B;
            B = D;
            D = tmp;
        }

        uint32_t T0 = g_func(A);
        uint32_t T1 = g_func(rol32(B, 8));
        uint32_t F0 = (T0 + T1 + m_subkeys[2 * r + 8]) & 0xFFFFFFFFu;
        uint32_t F1 = (T0 + 2 * T1 + m_subkeys[2 * r + 9]) & 0xFFFFFFFFu;

        C = rol32(C, 1) ^ F0;
        D = ror32(D ^ F1, 1);
        }

        A ^= m_subkeys[0];
        B ^= m_subkeys[1];
        C ^= m_subkeys[2];
        D ^= m_subkeys[3];

        Bytes result(16);
        result[0] = (uint8_t)(A);
        result[1] = (uint8_t)(A >> 8);
        result[2] = (uint8_t)(A >> 16);
        result[3] = (uint8_t)(A >> 24);
        result[4] = (uint8_t)(B);
        result[5] = (uint8_t)(B >> 8);
        result[6] = (uint8_t)(B >> 16);
        result[7] = (uint8_t)(B >> 24);
        result[8] = (uint8_t)(C);
        result[9] = (uint8_t)(C >> 8);
        result[10] = (uint8_t)(C >> 16);
        result[11] = (uint8_t)(C >> 24);
        result[12] = (uint8_t)(D);
        result[13] = (uint8_t)(D >> 8);
        result[14] = (uint8_t)(D >> 16);
        result[15] = (uint8_t)(D >> 24);
        return result;
    }
}