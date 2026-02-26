#include <iostream>
#include <iomanip>
#include <random>
#include <chrono>
#include <filesystem>
#include "src/core/DESCipher.hpp"
#include "src/core/CryptoProcessor.hpp"
#include "src/core/DESCipher.hpp"

using namespace crypto;

void printBytes(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min<size_t>(16, data.size()); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > 16) std::cout << "...";
    std::cout << std::dec << std::endl;
}

std::vector<uint8_t> generateRandomData(size_t size) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 255);
    
    std::vector<uint8_t> result(size);
    for (auto& b : result) {
        b = static_cast<uint8_t>(dis(gen));
    }
    return result;
}

void testDES() {
    std::cout << "\n=== Testing DES Algorithm ===\n" << std::endl;
    
    auto des = std::make_unique<DESCipher>();
    CryptoProcessor processor(std::move(des));
    
    // Тестовый ключ (8 байт)
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    processor.setKey(key);
    
    // Тест 1: Шифрование одного блока (8 байт)
    std::vector<uint8_t> testData1 = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    std::cout << "Test 1: Single block (8 bytes)\n";
    printBytes("Original", testData1);
    
    std::vector<uint8_t> encrypted1 = processor.encryptData(testData1);
    printBytes("Encrypted", encrypted1);
    
    std::vector<uint8_t> decrypted1 = processor.decryptData(encrypted1);
    printBytes("Decrypted", decrypted1);
    
    if (testData1 == decrypted1) {
        std::cout << "✓ Single block test PASSED\n";
    } else {
        std::cout << "✗ Single block test FAILED\n";
    }
    
    // Тест 2: Шифрование двух блоков (16 байт)
    std::vector<uint8_t> testData2 = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    std::cout << "\nTest 2: Two blocks (16 bytes)\n";
    printBytes("Original", testData2);
    
    std::vector<uint8_t> encrypted2 = processor.encryptData(testData2);
    printBytes("Encrypted", encrypted2);
    
    std::vector<uint8_t> decrypted2 = processor.decryptData(encrypted2);
    printBytes("Decrypted", decrypted2);
    
    if (testData2 == decrypted2) {
        std::cout << "✓ Two blocks test PASSED\n";
    } else {
        std::cout << "✗ Two blocks test FAILED\n";
    }
}

void testFileEncryption() {
    std::cout << "\n=== Testing File Encryption/Decryption ===\n" << std::endl;
    
    auto des = std::make_unique<DESCipher>();
    CryptoProcessor processor(std::move(des));
    
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    processor.setKey(key);
    
    // Создаем тестовые файлы разных типов
    std::cout << "Creating test files...\n";
    
    // 1. Текстовый файл (кратный 8 байтам)
    {
        std::ofstream file("test_text.txt");
        file << "01234567ABCDEFGH"; // 16 байт (2 блока)
        std::cout << "Created test_text.txt (16 bytes)\n";
    }
    
    // 2. Бинарный файл со случайными данными (кратный 8 байтам)
    {
        std::vector<uint8_t> randomData = generateRandomData(1024); // 1KB (128 блоков)
        std::ofstream file("test_data.bin", std::ios::binary);
        file.write(reinterpret_cast<const char*>(randomData.data()), randomData.size());
        std::cout << "Created test_data.bin (1024 bytes)\n";
    }
    
    std::cout << "\n--- Testing text file ---\n";
    // Шифрование текстового файла
    try {
        processor.encryptFile("test_text.txt", "test_text.enc");
        processor.decryptFile("test_text.enc", "test_text_dec.txt");
        
        // Проверяем результат
        std::vector<uint8_t> original = processor.readFile("test_text.txt");
        std::vector<uint8_t> decrypted = processor.readFile("test_text_dec.txt");
        
        if (original == decrypted) {
            std::cout << "✓ Text file test PASSED\n";
            std::string content(decrypted.begin(), decrypted.end());
            std::cout << "Decrypted content: " << content << std::endl;
        } else {
            std::cout << "✗ Text file test FAILED\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
    
    std::cout << "\n--- Testing binary file ---\n";
    // Шифрование бинарного файла
    try {
        processor.encryptFile("test_data.bin", "test_data.enc");
        processor.decryptFile("test_data.enc", "test_data_dec.bin");
        
        // Проверяем результат
        std::vector<uint8_t> original = processor.readFile("test_data.bin");
        std::vector<uint8_t> decrypted = processor.readFile("test_data_dec.bin");
        
        if (original == decrypted) {
            std::cout << "✓ Binary file test PASSED\n";
            std::cout << "First 16 bytes of original: ";
            printBytes("", std::vector<uint8_t>(original.begin(), original.begin() + 16));
            std::cout << "First 16 bytes of decrypted: ";
            printBytes("", std::vector<uint8_t>(decrypted.begin(), decrypted.begin() + 16));
        } else {
            std::cout << "✗ Binary file test FAILED\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

void testImageFile(const std::string& imagePath) {
    std::cout << "\n=== Testing Image File Encryption ===\n" << std::endl;
    
    if (!std::filesystem::exists(imagePath)) {
        std::cout << "Image file not found: " << imagePath << std::endl;
        std::cout << "Skipping image test.\n";
        return;
    }
    
    auto des = std::make_unique<DESCipher>();
    CryptoProcessor processor(std::move(des));
    
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    processor.setKey(key);
    
    try {
        std::cout << "Processing image: " << imagePath << std::endl;
        
        // Проверяем размер файла
        std::vector<uint8_t> original = processor.readFile(imagePath);
        std::cout << "Original size: " << original.size() << " bytes" << std::endl;
        
        if (original.size() % 8 != 0) {
            std::cout << "Warning: Image size is not multiple of 8 bytes (" 
                      << original.size() % 8 << " bytes remainder)" << std::endl;
            std::cout << "For DES encryption, we'll only process the first " 
                      << (original.size() - (original.size() % 8)) << " bytes\n";
            
            // Обрезаем до кратного 8 размера
            original.resize(original.size() - (original.size() % 8));
        }
        
        // Шифруем
        std::string encPath = "encrypted_" + std::filesystem::path(imagePath).filename().string();
        std::string decPath = "decrypted_" + std::filesystem::path(imagePath).filename().string();
        
        // Сохраняем оригинал (обрезанный) во временный файл
        processor.writeFile("temp_original.bin", original);
        
        // Шифруем и дешифруем
        processor.encryptFile("temp_original.bin", encPath);
        processor.decryptFile(encPath, decPath);
        
        // Проверяем результат
        std::vector<uint8_t> decrypted = processor.readFile(decPath);
        
        if (original == decrypted) {
            std::cout << "✓ Image encryption/decryption test PASSED\n";
            std::cout << "Encrypted file: " << encPath << std::endl;
            std::cout << "Decrypted file: " << decPath << std::endl;
        } else {
            std::cout << "✗ Image encryption/decryption test FAILED\n";
        }
        
        // Удаляем временный файл
        std::filesystem::remove("temp_original.bin");
        
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

void benchmarkDES() {
    std::cout << "\n=== Performance Benchmark ===\n" << std::endl;
    
    auto des = std::make_unique<crypto::DESCipher>();
    CryptoProcessor processor(std::move(des));
    
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    processor.setKey(key);
    
    // Тест с разными размерами данных (кратными 8)
    std::vector<size_t> sizes = {1024, 10240, 102400, 1048576}; // 1KB, 10KB, 100KB, 1MB
    
    for (size_t size : sizes) {
        std::vector<uint8_t> data = generateRandomData(size);
        
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> encrypted = processor.encryptData(data);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double speed = (static_cast<double>(size) / duration.count()) * 1000000 / (1024 * 1024); // MB/s
        
        std::cout << "Size: " << size / 1024 << " KB, "
                  << "Time: " << duration.count() / 1000.0 << " ms, "
                  << "Speed: " << std::fixed << std::setprecision(2) << speed << " MB/s\n";
    }
}

int main(int argc, char* argv[]) {
    try {
        std::cout << "========================================\n";
        std::cout << "   Simple DES File Encryption Demo\n";
        std::cout << "========================================\n";
        
        // Тест DES с блоками данных
        testDES();
        
        // Тест шифрования файлов
        testFileEncryption();
        
        // Тест шифрования изображения (если передан путь к изображению)
        if (argc > 1) {
            testImageFile(argv[1]);
        } else {
            std::cout << "\nTo test image encryption, run: " << argv[0] << " <path_to_image>\n";
        }
        
        // Производительность
        benchmarkDES();
        
        std::cout << "\nAll tests completed!\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}