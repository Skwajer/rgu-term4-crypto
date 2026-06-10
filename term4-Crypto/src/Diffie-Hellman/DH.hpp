#ifndef DIFFIE_HELLMAN_HPP
#define DIFFIE_HELLMAN_HPP

#include "../../math/NumberTheoryService.hpp"
#include <string>
#include <vector>
#include <cstdint>

class DiffieHellman {
private:
    BigInt p;
    BigInt g;
    BigInt privateKey;
    BigInt publicKey; 
    BigInt sharedSecret; 
    
    NumberTheoryService nts;
    
public:
    DiffieHellman(int bits = 512);
    
    DiffieHellman(const BigInt& prime, const BigInt& generator);
    
    void generatePublicKey();
    
    void computeSharedSecret(const BigInt& otherPublicKey);
    
    BigInt getSharedSecret() const;
    
    BigInt getPublicKey() const;
    
    BigInt getPrime() const { return p; }
    BigInt getGenerator() const { return g; }
    
    std::vector<uint8_t> generateDESKey() const;
    std::vector<uint8_t> generateAES128Key() const;
    std::vector<uint8_t> generateAES192Key() const;
    std::vector<uint8_t> generateAES256Key() const;
    std::vector<uint8_t> generateMARS128Key() const;
    std::vector<uint8_t> generateMARS192Key() const;
    std::vector<uint8_t> generateMARS256Key() const;
    
    std::vector<uint8_t> generateKey(size_t keyBytes) const;
    
    static std::vector<uint8_t> bigIntToBytes(const BigInt& value);
    static std::vector<uint8_t> bigIntToBytes(const BigInt& value, size_t size);
};

#endif // DIFFIE_HELLMAN_HPP