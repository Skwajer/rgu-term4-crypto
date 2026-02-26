#pragma once
#include "ISymmetricCipher.hpp"
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <stdint.h>

namespace crypto {
    class CryptoProcessor {
    private:
        std::unique_ptr<ISymmetricCipher> cipher_;
        
    public:
        explicit CryptoProcessor(std::unique_ptr<ISymmetricCipher> cipher);
        
        // Установка ключа
        void setKey(const std::vector<uint8_t>& key);
        
        // Шифрование/дешифрование данных (размер должен быть кратен 8 байтам)
        std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data);
        std::vector<uint8_t> decryptData(const std::vector<uint8_t>& data);
        
        // Работа с файлами
        void encryptFile(const std::string& inputPath, const std::string& outputPath);
        void decryptFile(const std::string& inputPath, const std::string& outputPath);
        
        // Вспомогательные функции для работы с файлами
        std::vector<uint8_t> readFile(const std::string& path);
        void writeFile(const std::string& path, const std::vector<uint8_t>& data);
    };
}