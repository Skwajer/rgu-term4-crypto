#include "../crypto_core/ISymmetricCipher.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace crypto 
{
    class MarsCipher final : public ISymmetricCipher
    {
    private:
        static constexpr size_t SUBKEYS_COUNT = 40;
        static constexpr size_t BLOCK_SIZE = 16;
        static constexpr size_t ROUNDS_COUNT = 32;

    public:
        MarsCipher();
        void setKey(Bytes const &key) override;
        size_t block_size() const override;

        Bytes encryptBlock(Bytes const &block) override;
        Bytes decryptBlock(Bytes const &block) override;


    private:
        void KeyExpansion(Bytes const &key);
        uint32_t rol32(uint32_t x, int n);
        uint32_t ror32(uint32_t x, int n);

    private:
        Bytes m_key;
        size_t m_key_size;
        std::array<uint32_t, SUBKEYS_COUNT> m_subkeys{};
    };
}