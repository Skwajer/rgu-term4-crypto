#include "DH.hpp"
#include <stdexcept>
#include <algorithm>
#include <cstring>

DiffieHellman::DiffieHellman(int bits) {
    std::cout << "  [DEBUG] Constructor with bits=" << bits << std::endl;
    
    std::cout << "  [DEBUG] Generating prime p..." << std::endl;
    p = nts.generate_prime(bits, 0.9);
    std::cout << "  [DEBUG] Prime p generated: " << p << std::endl;
    
    std::cout << "  [DEBUG] Finding primitive root g..." << std::endl;
    g = nts.find_primitive_root_for_prime(p);
    std::cout << "  [DEBUG] Primitive root g: " << g << std::endl;
    
    if (g == -1) {
        std::cout << "  [DEBUG] No primitive root found, trying another p..." << std::endl;
        while (g == -1) {
            p = nts.generate_prime(bits, 0.9);
            g = nts.find_primitive_root_for_prime(p);
        }
    }
    
    std::cout << "  [DEBUG] Generating private key..." << std::endl;
    privateKey = nts.generate_random_bigint(2, p - 2);
    std::cout << "  [DEBUG] Private key: " << privateKey << std::endl;
    
    std::cout << "  [DEBUG] Generating public key..." << std::endl;
    generatePublicKey();
    std::cout << "  [DEBUG] Constructor finished" << std::endl;
}

DiffieHellman::DiffieHellman(const BigInt& prime, const BigInt& generator) 
    : p(prime), g(generator) {
    
    privateKey = nts.generate_random_bigint(2, p - 2);
    
    generatePublicKey();
}

void DiffieHellman::generatePublicKey() {
    publicKey = nts.pow_mod(g, privateKey, p);
}

void DiffieHellman::computeSharedSecret(const BigInt& otherPublicKey) {
    sharedSecret = nts.pow_mod(otherPublicKey, privateKey, p);
}

BigInt DiffieHellman::getSharedSecret() const {
    return sharedSecret;
}

BigInt DiffieHellman::getPublicKey() const {
    return publicKey;
}

std::vector<uint8_t> DiffieHellman::bigIntToBytes(const BigInt& value) {
    std::vector<uint8_t> result;
    
    if (value == 0) {
        result.push_back(0);
        return result;
    }
    
    BigInt temp = value;
    while (temp > 0) {
        result.push_back(static_cast<uint8_t>(temp % 256));
        temp /= 256;
    }
    
    std::reverse(result.begin(), result.end());
    
    return result;
}

std::vector<uint8_t> DiffieHellman::bigIntToBytes(const BigInt& value, size_t size) {
    std::vector<uint8_t> bytes = bigIntToBytes(value);
    std::vector<uint8_t> result(size, 0);
    
    size_t copySize = std::min(bytes.size(), size);
    for (size_t i = 0; i < copySize; i++) {
        result[size - copySize + i] = bytes[i];
    }
    
    return result;
}

std::vector<uint8_t> DiffieHellman::generateKey(size_t keyBytes) const {
    std::vector<uint8_t> secretBytes = bigIntToBytes(sharedSecret);
    std::vector<uint8_t> key(keyBytes, 0);
    
    size_t bytesToCopy = std::min(keyBytes, secretBytes.size());
    for (size_t i = 0; i < bytesToCopy; i++) {
        key[i] = secretBytes[i];
    }
    
    for (size_t i = secretBytes.size(); i < keyBytes; i++) {
        key[i] = 0;
    }
    
    return key;
}

std::vector<uint8_t> DiffieHellman::generateDESKey() const {
    std::vector<uint8_t> key = generateKey(8);
    
    for (int i = 0; i < 8; i++) {
        int parity = 0;
        for (int j = 0; j < 7; j++) {
            if (key[i] & (1 << j)) parity++;
        }
        if (parity % 2 == 0) {
            key[i] |= 0x80;
        } else {
            key[i] &= 0x7F;
        }
    }
    
    return key;
}

std::vector<uint8_t> DiffieHellman::generateAES128Key() const {
    // AES-128: 16 байт (128 бит)
    return generateKey(16);
}

std::vector<uint8_t> DiffieHellman::generateAES192Key() const {
    // AES-192: 24 байта (192 бита)
    return generateKey(24);
}

std::vector<uint8_t> DiffieHellman::generateAES256Key() const {
    // AES-256: 32 байта (256 бит)
    return generateKey(32);
}

std::vector<uint8_t> DiffieHellman::generateMARS128Key() const {
    // MARS-128: 16 байт (128 бит)
    return generateKey(16);
}

std::vector<uint8_t> DiffieHellman::generateMARS192Key() const {
    // MARS-192: 24 байта (192 бита)
    return generateKey(24);
}

std::vector<uint8_t> DiffieHellman::generateMARS256Key() const {
    // MARS-256: 32 байта (256 бит)
    return generateKey(32);
}