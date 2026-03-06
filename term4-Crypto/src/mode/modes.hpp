#include "../crypto_core/namespaces_crypto.hpp"
#include "../crypto_core/ISymmetricCipher.hpp"

namespace crypto
{
  class CipherMode
  {
  public:
      virtual void encrypt(ISymmetricCipher &cipher, const Bytes &input,
      Bytes &output, size_t threads);
      virtual void decrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads);
  };


  class ECB final : public CipherMode 
  {
  public:
    void encrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads) override;
    void decrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads) override;

  private:
    static void process(ISymmetricCipher &cipher, const Bytes &input,
                        Bytes &output, size_t threads, bool encrypting);
  };

  class CBC final : public CipherMode 
  {
  public:
    explicit CBC(Bytes iv = {});
    void encrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads) override;
    void decrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads) override;

  private:
    Bytes get_iv(size_t bs) const;
    Bytes m_iv;
  };

  class PCBC final : public CipherMode 
  {
  public:
    explicit PCBC(Bytes iv = {});
    void encrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads) override;
    void decrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads) override;

  private:
    Bytes get_iv(size_t bs) const;
    Bytes m_iv;
  };

}