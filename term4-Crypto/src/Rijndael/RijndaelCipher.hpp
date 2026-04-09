#pragma once
#include "../crypto_core/namespaces_crypto.hpp"
#include "../crypto_core/ISymmetricCipher.hpp"
#include <cstddef>
#include <cstdint>
#include <vector>
#include "../../math/GF2n/gf2n.hpp"

namespace crypto 
{
    class RijndaelCipher : public ISymmetricCipher 
    {
    public:
        void generateRoundKeys(const Bytes& key);
        Bytes encryptBlock(const Bytes& block) override;
        Bytes decryptBlock(const Bytes& block) override;

        void setKey(const Bytes& key) override;
        size_t block_size() const override;
                
    public:
        RijndaelCipher(GF2n::u64 gf8_mod, size_t block_bits = 128, size_t key_bits = 128);

    private:
        Byte affineTransform(GF2n::u64 b) const noexcept;
        void calculate_s_box(GF2n::u64 mod) noexcept;
        void SubBytes(std::vector<Byte> &state) noexcept;
        void ShiftRows(std::vector<Byte> &state) const noexcept;
        void MixColumns(std::vector<Byte> &state) noexcept;
        void AddRoundKey(std::vector<Byte>& state, size_t round) noexcept;

    private:
        void InvSubBytes(std::vector<Byte> &state);
        void InvShiftRows(std::vector<Byte> &state);
        void InvMixColumns(std::vector<Byte> &state);

    private:
        uint32_t SubWord(uint32_t word);
        uint32_t RotWord(uint32_t word);
        uint32_t Rcon(size_t i);

    private:
        // size in bytes
        size_t m_block_size;
        size_t m_key_size;
        size_t m_rounds;
        std::vector<uint32_t> m_w;
        Byte m_s_box[256];
        Byte m_inv_s_box[256];
        GF2n m_gf8;
    };
}