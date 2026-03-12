#include "../crypto_core/namespaces_crypto.hpp"
#include <random>
#include <ctime>

namespace crypto 
{
class IPadding
{
  public:
    virtual ~IPadding() = default;
    virtual Bytes apply(const Bytes &data, size_t block_size) const = 0;
    virtual Bytes remove(const Bytes &data, size_t block_size) const = 0;
  };

  class ZerosPadding final : public IPadding
  {
  public:
    Bytes apply(const Bytes &data, size_t block_size) const override;
    Bytes remove(const Bytes &data, size_t block_size) const override;
  };

  class AnsiX923Padding final : public IPadding
  {
  public:
    Bytes apply(const Bytes &data, size_t block_size) const override;
    Bytes remove(const Bytes &data, size_t block_size) const override;
  };

  class PKCS7Padding final : IPadding
  {
    public:
    Bytes apply(const Bytes &data, size_t block_size) const override;
    Bytes remove(const Bytes &data, size_t block_size) const override;
  };

  class ISO10126Padding final : IPadding
  {
    public:
    Bytes apply(const Bytes &data, size_t block_size) const override;
    Bytes remove(const Bytes &data, size_t block_size) const override;
  };
}