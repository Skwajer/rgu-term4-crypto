#include "../crypto_core/namespaces_crypto.hpp"
#include "../crypto_core/ISymmetricCipher.hpp"
#include <cstdint>
#include <random>

namespace crypto
{
  class CipherMode
  {
  public:
      virtual ~CipherMode() = default;
      virtual void encrypt(ISymmetricCipher &cipher, const Bytes &input,
      Bytes &output, size_t threads) = 0;
      virtual void decrypt(ISymmetricCipher &cipher, const Bytes &input,
                Bytes &output, size_t threads) = 0;
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
    void validate_iv(size_t bs) const;
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
    void validate_iv(size_t bs) const;
    Bytes m_iv;
  };

  class CFB final : public CipherMode {
public:
  explicit CFB(Bytes iv = {});
  void encrypt(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads) override;
  void decrypt(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads) override;

private:
  Bytes get_iv(size_t bs) const;
  Bytes m_iv;
};

class OFB final : public CipherMode {
public:
  explicit OFB(Bytes iv = {});
  void encrypt(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads) override;
  void decrypt(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads) override;

private:
  Bytes get_iv(size_t bs) const;
  static void process(ISymmetricCipher &cipher, const Bytes &iv,
                      const Bytes &input, Bytes &output);
  Bytes m_iv;
};

class CTR final : public CipherMode {
public:
  explicit CTR(Bytes nonce = {});
  void encrypt(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads) override;
  void decrypt(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads) override;

private:
  void process(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads);
  static Bytes make_counter_block(const Bytes &nonce, uint64_t counter,
                                        size_t bs);
  Bytes m_nonce;
};


class RD final : public CipherMode {
public:
  explicit RD(uint64_t seed = 0);
  void encrypt(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads) override;
  void decrypt(ISymmetricCipher &cipher, const Bytes &input,
               Bytes &output, size_t threads) override;

private:
  uint64_t m_seed;
};


}