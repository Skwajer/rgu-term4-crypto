#include "CryptoProcessor.hpp"
#include <stdexcept>
#include <iterator>
#include <fstream>
#include <vector>
#include <algorithm>
#include <iostream>

namespace crypto {

CryptoProcessor::CryptoProcessor(std::unique_ptr<ISymmetricCipher> cipher)
    : cipher_(std::move(cipher)) {
    if (!cipher_) {
        throw std::invalid_argument("Cipher must be provided");
    }
}

void CryptoProcessor::setKey(const std::vector<uint8_t>& key) {
    cipher_->setKey(key);
}

std::vector<uint8_t> CryptoProcessor::encryptData(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::vector<uint8_t>();
    }
    
    if (data.size() % 8 != 0) {
        throw std::runtime_error("Data size must be multiple of 8 bytes for DES encryption");
    }
    
    std::vector<uint8_t> result;
    result.reserve(data.size());
    
    // Шифруем по блокам (8 байт)
    for (size_t i = 0; i < data.size(); i += 8) {
        std::vector<uint8_t> block(data.begin() + i, data.begin() + i + 8);
        std::vector<uint8_t> encrypted = cipher_->encryptBlock(block);
        result.insert(result.end(), encrypted.begin(), encrypted.end());
    }
    
    return result;
}

std::vector<uint8_t> CryptoProcessor::decryptData(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::vector<uint8_t>();
    }
    
    if (data.size() % 8 != 0) {
        throw std::runtime_error("Encrypted data size must be multiple of 8 bytes");
    }
    
    std::vector<uint8_t> result;
    result.reserve(data.size());
    
    // Дешифруем по блокам (8 байт)
    for (size_t i = 0; i < data.size(); i += 8) {
        std::vector<uint8_t> block(data.begin() + i, data.begin() + i + 8);
        std::vector<uint8_t> decrypted = cipher_->decryptBlock(block);
        result.insert(result.end(), decrypted.begin(), decrypted.end());
    }
    
    return result;
}

std::vector<uint8_t> CryptoProcessor::readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file for reading: " + path);
    }
    
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
}

void CryptoProcessor::writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot create file for writing: " + path);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void CryptoProcessor::encryptFile(const std::string& inputPath,
                                  const std::string& outputPath) {
    std::vector<uint8_t> data = readFile(inputPath);
    
    // Проверяем размер файла
    if (data.size() % 8 != 0) {
        throw std::runtime_error("File size must be multiple of 8 bytes for DES encryption");
    }
    
    std::vector<uint8_t> encrypted = encryptData(data);
    writeFile(outputPath, encrypted);
    
    std::cout << "File encrypted successfully: " << inputPath << " -> " << outputPath << std::endl;
    std::cout << "Size: " << data.size() << " bytes -> " << encrypted.size() << " bytes" << std::endl;
}

void CryptoProcessor::decryptFile(const std::string& inputPath,
                                  const std::string& outputPath) {
    std::vector<uint8_t> data = readFile(inputPath);
    
    // Проверяем размер зашифрованного файла
    if (data.size() % 8 != 0) {
        throw std::runtime_error("Encrypted file size must be multiple of 8 bytes");
    }
    
    std::vector<uint8_t> decrypted = decryptData(data);
    writeFile(outputPath, decrypted);
    
    std::cout << "File decrypted successfully: " << inputPath << " -> " << outputPath << std::endl;
    std::cout << "Size: " << data.size() << " bytes -> " << decrypted.size() << " bytes" << std::endl;
}

} // namespace crypto