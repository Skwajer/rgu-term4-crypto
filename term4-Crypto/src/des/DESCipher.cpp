#include "DESCipher.hpp"
#include <cstring>
#include <stdint.h>
#include <vector>
#include "des_tables.cpp"
#include "../crypto_core/namespaces_crypto.hpp"
#include "../bits/Pbox_permutation.hpp"
#include "../bits/Sbox_substitution.hpp"

namespace crypto 
{

DESCipher::DESCipher() : FeistelCipher(
        std::make_unique<FeistelNetwork>(
            std::make_unique<DESRoundFunction>(),
            std::make_unique<DESKeyExpansion>(),
            16
        )
    ) {}

std::vector<uint8_t> rotate_left(const std::vector<uint8_t> &bits,
                                size_t n_bits, size_t shift) 
{
    if (bits.empty() || n_bits == 0)
        return {};

    shift %= n_bits;
    if (shift == 0)
        return bits;

    std::vector<uint8_t> res;
    size_t bytes_needed = (n_bits + 7) / 8;
    res.resize(bytes_needed, 0);

    for (size_t i = 0; i < n_bits; i++) 
    {
        size_t new_pos = (i + shift) % n_bits;
        
        size_t src_byte = i / 8;
        size_t src_bit = 7 - (i % 8);
        size_t dst_byte = new_pos / 8;
        size_t dst_bit = 7 - (new_pos % 8);

        uint8_t bit_val = (bits[src_byte] >> src_bit) & 1;
        
        if (bit_val) 
        {
            res[dst_byte] |= (1 << dst_bit);
        } else {
            res[dst_byte] &= ~(1 << dst_bit);
        }
    }

    return res;
}
    
std::vector<Bytes> DESCipher::DESKeyExpansion::generateRoundKeys(const std::vector<uint8_t>& key) 
{
    
    std::vector<Bytes> roundKeys(16);
    
    auto cd = bit_Pbox_permutation(key, PC1, BitOrder::BIG_END,
                      BitCountingBase::ONE);
    auto C = bit_Pbox_permutation(cd, SPLIT_C, BitOrder::BIG_END,
                      BitCountingBase::ONE);
    auto D = bit_Pbox_permutation(cd, SPLIT_D, BitOrder::BIG_END,
                      BitCountingBase::ONE);
    

    for (auto round = 0; round < 16; round++)
    {
        
        C = rotate_left(C, 28, DES_KEY_SHIFTS[round]);
        D = rotate_left(D, 28, DES_KEY_SHIFTS[round]);
        
        Bytes CD;
        CD.insert(CD.end(), C.begin(), C.end());
        CD.insert(CD.end(), D.begin(), D.end());
        
        CD = bit_Pbox_permutation(CD, COMPACT_CD, BitOrder::BIG_END,
                          BitCountingBase::ONE);
        


        auto roundKey = bit_Pbox_permutation(CD, PC2, BitOrder::BIG_END,
                          BitCountingBase::ONE);
        


        roundKeys[round] = std::move(roundKey);
    }
    
    return roundKeys;
}

    Bytes DESCipher::DESRoundFunction::encryptRound(const Bytes& block, const Bytes& roundKey)
{
    auto E_block = bit_Pbox_permutation(block, E, BIG_END, ONE);
    
    Bytes xored_block(6);
    for (size_t i = 0; i < 6; i++) {
        xored_block[i] = E_block[i] ^ roundKey[i];
    }
    
    Bytes substituted_sparce(8, 0);

    for (int i = 0; i < 8; i++) 
    {
        size_t bit_offset = i * 6;

        std::vector<size_t> indices = {bit_offset,     bit_offset + 1,
                                    bit_offset + 2, bit_offset + 3,
                                    bit_offset + 4, bit_offset + 5};
        std::vector<uint8_t> six_bits =
            bit_Pbox_permutation(xored_block, indices, BIG_END,
                        ZERO);

        std::vector<uint8_t> four_bits =
            substitute(six_bits, SBOXES[i], 6, 4);

        substituted_sparce[i] = four_bits[0];
    }

    Bytes substituted =
        bit_Pbox_permutation(substituted_sparce, COMPACT_64_32,
                        BIG_END, ONE);

    auto final_block =
        bit_Pbox_permutation(substituted, P, BIG_END,
                        ONE);
    
    return final_block;
}

    void DESCipher::preEncrypt(std::vector<Byte> &block) 
    {
        if (block.size() != 8) return;
        
        block = bit_Pbox_permutation(block, IP, BIG_END, ONE);
    }
    
    void DESCipher::postEncrypt(std::vector<uint8_t> &block) 
    {
        if (block.size() != 8) return;
        
        block = bit_Pbox_permutation(block, FP, BIG_END, ONE);
    }

    size_t DESCipher::block_size() const
    {
        return 8;
    }

}