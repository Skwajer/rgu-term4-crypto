#include "../crypto_core/ISymmetricCipher.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace crypto 
{
    class TwofishCipher final : public ISymmetricCipher
    {
    private:
        static constexpr size_t SUBKEYS_COUNT = 40;
        static constexpr size_t BLOCK_SIZE = 16;
        static constexpr size_t ROUNDS_COUNT = 16;

    public:
        TwofishCipher();
        void setKey(Bytes const &key) override;
        size_t block_size() const override;

        Bytes encryptBlock(Bytes const &block) override;
        Bytes decryptBlock(Bytes const &block) override;


    private:
        uint32_t rol32(uint32_t x, int n);
        uint32_t ror32(uint32_t x, int n);
        uint32_t h_func(uint32_t X, std::vector<uint32_t> const &L, size_t k);
        uint32_t g_func(uint32_t X);

        void KeySchedule(Bytes const &key);

    private:
        Bytes m_key;
        size_t m_key_size;
        std::array<uint32_t, SUBKEYS_COUNT> m_subkeys{};
        std::array<std::array<uint8_t, 256>, 4> m_sboxs{};
    };
}










