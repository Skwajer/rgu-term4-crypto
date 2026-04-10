# rgu-term4-crypto

Cryptography labs, 4th semester.

## What's inside

### Ciphers
- **DES** – block cipher implementation
- **Rijndael** - supports block sizes of 128, 192, 256 bits and key sizes of 128, 192, 256 bits
- **RSA** – asymmetric encryption
- **Common interfaces** – unified API for symmetric (including Feistel network) ciphers. Using ciphers through           CipherContext API that supports various cipher modes, paddings and multithreaded encryption/decription

### Math library
- **Polynomials over GF(2^n)**
- **NumberTheoryService** - set of static functions to work with Big integer numbers from boost/multiprecision/
- **Primality tests (probabilistic):**
  - Fermat test
  - Solovay–Strassen test
  - Miller–Rabin test

### Testing
- **Google Test**

