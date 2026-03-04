#include "src/core/DESCipher.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
#include <cassert>

using namespace crypto;

void printBytes(const Bytes& bytes, const std::string& label) {
    std::cout << label << ": ";
    for (auto b : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(b) << " ";
    }
    std::cout << std::dec << std::endl;
}

bool compareBytes(const Bytes& expected, const Bytes& actual, 
                  const std::string& testName) {
    if (expected.size() != actual.size()) {
        std::cout << testName << " FAILED: Size mismatch. Expected " 
                  << expected.size() << " bytes, got " << actual.size() << " bytes" << std::endl;
        return false;
    }
    
    bool match = true;
    for (size_t i = 0; i < expected.size(); i++) {
        if (expected[i] != actual[i]) {
            std::cout << testName << " FAILED at byte " << i 
                      << ": Expected 0x" << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(expected[i]) 
                      << ", got 0x" << static_cast<int>(actual[i]) << std::dec << std::endl;
            match = false;
            break;
        }
    }
    
    if (match) {
        std::cout << testName << " PASSED" << std::endl;
    }
    
    return match;
}

// Тест 1: Проверка генерации раундовых ключей через IKeyExpansion интерфейс
void testKeyExpansion() {
    std::cout << "\n=== Тест 1: Генерация раундовых ключей DES ===\n" << std::endl;
    
    // Тестовый ключ: 0x0123456789ABCDEF
    Bytes key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    

    std::vector<Bytes> expectedRoundKeys = {
        {0x18, 0x12, 0x34, 0x56, 0x78, 0x90}, // Раунд 1 (примерные значения, нужно заменить на реальные из спецификации)
    };
    std::unique_ptr<IKeyExpansion> keyExpansion = std::make_unique<DESCipher::DESKeyExpansion>();
    auto roundKeys = keyExpansion->generateRoundKeys(key);
    
    std::cout << "Сгенерировано " << roundKeys.size() << " раундовых ключей" << std::endl;
    assert(roundKeys.size() == 16 && "Должно быть 16 раундовых ключей");
    
    // Выводим все сгенерированные ключи
    for (size_t i = 0; i < roundKeys.size(); i++) {
        std::cout << "K" << (i + 1) << ": ";
        printBytes(roundKeys[i], "");
    }
    
    // Проверяем размер каждого ключа (должен быть 6 байт = 48 бит)
    for (size_t i = 0; i < roundKeys.size(); i++) {
        if (roundKeys[i].size() != 6) {
            std::cout << "✗ Раундовый ключ " << (i + 1) << " имеет неправильный размер: " 
                      << roundKeys[i].size() << " байт (ожидалось 6)" << std::endl;
        } else {
            std::cout << "✓ K" << (i + 1) << " имеет правильный размер (6 байт)" << std::endl;
        }
    }
    
    // Проверяем, что ключи различаются между раундами
    bool allDifferent = true;
    for (size_t i = 0; i < roundKeys.size() - 1; i++) {
        if (roundKeys[i] == roundKeys[i + 1]) {
            std::cout << "✗ Раундовые ключи " << (i + 1) << " и " << (i + 2) 
                      << " идентичны!" << std::endl;
            allDifferent = false;
        }
    }
    
    if (allDifferent) {
        std::cout << "✓ Все раундовые ключи различны" << std::endl;
    }
}

// Тест 2: Проверка работы раундовой функции через IFeistelRound интерфейс
void testRoundFunction() {
    std::cout << "\n=== Тест 2: Проверка раундовой функции DES ===\n" << std::endl;
    
    // Правая половина блока (32 бита)
    Bytes rightHalf = {0x12, 0x34, 0x56, 0x78};
    
    // Раундовый ключ (48 бит)
    Bytes roundKey = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
    
    std::unique_ptr<IFeistelRound> roundFunction = std::make_unique<DESCipher::DESRoundFunction>();
    
    auto result = roundFunction->encryptRound(rightHalf, roundKey);
    
    std::cout << "Правая половина (R): ";
    printBytes(rightHalf, "");
    std::cout << "Раундовый ключ (K): ";
    printBytes(roundKey, "");
    std::cout << "Результат f(R,K): ";
    printBytes(result, "");
    
    // Результат раундовой функции должен быть 32 бита (4 байта)
    if (result.size() == 4) {
        std::cout << "✓ Результат имеет правильный размер (4 байта)" << std::endl;
    } else {
        std::cout << "✗ Неправильный размер: " << result.size() << " байт" << std::endl;
    }
}

// Тест 3: Тестирование FeistelNetwork с DES компонентами
void testFeistelNetwork() {
    std::cout << "\n=== Тест 3: Тестирование FeistelNetwork с DES ===\n" << std::endl;
    
    // Создаем компоненты DES
    auto roundFunction = std::make_unique<DESCipher::DESRoundFunction>();
    auto keyExpansion = std::make_unique<DESCipher::DESKeyExpansion>();
    
    // Создаем сеть Фейстеля с 16 раундами (как в DES)
    FeistelNetwork network(std::move(roundFunction), std::move(keyExpansion), 16);
    
    // Тестовый ключ и блок
    Bytes key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    Bytes plaintext = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    std::cout << "Ключ: ";
    printBytes(key, "");
    std::cout << "Исходный текст: ";
    printBytes(plaintext, "");

    network.set_round_keys(key);
    
    // Шифруем
    Bytes ciphertext = network.encrypt(plaintext);
    std::cout << "Зашифровано: ";
    printBytes(ciphertext, "");
    
    // Дешифруем
    Bytes decrypted = network.decrypt(ciphertext);
    std::cout << "Расшифровано: ";
    printBytes(decrypted, "");
    
    // Проверяем обратимость
    if (plaintext == decrypted) {
        std::cout << "✓ Обратимость работает правильно!" << std::endl;
    } else {
        std::cout << "✗ Обратимость нарушена!" << std::endl;
    }
}

// Тест 4: Полное тестирование DESCipher через ISymmetricCipher интерфейс
void testDESCipherWithKnownVector() 
{
    std::cout << "\n=== Тест 4: DESCipher с известным тестовым вектором ===\n" << std::endl;
    
    // Известный тестовый вектор из спецификации DES
    Bytes key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    Bytes plaintext = {0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74}; // "Now is t"
    Bytes expectedCiphertext = {0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15};
    
    std::cout << "Ключ: ";
    printBytes(key, "");
    std::cout << "Открытый текст: ";
    printBytes(plaintext, "");
    std::cout << "Ожидаемый шифротекст: ";
    printBytes(expectedCiphertext, "");
    
    // Создаем шифр через базовый интерфейс
    std::unique_ptr<ISymmetricCipher> cipher = std::make_unique<DESCipher>();
    
    // Устанавливаем ключ
    cipher->setKey(key);
    
    // Шифруем блок
    Bytes ciphertext = cipher->encryptBlock(plaintext);
    
    std::cout << "Полученный шифротекст: ";
    printBytes(ciphertext, "");
    
    // Сравниваем с ожидаемым результатом
    compareBytes(expectedCiphertext, ciphertext, "DES шифрование с известным вектором");
    
    // Проверяем дешифрование
    Bytes decrypted = cipher->decryptBlock(ciphertext);
    std::cout << "Расшифрованный текст: ";
    printBytes(decrypted, "");
    
    compareBytes(plaintext, decrypted, "DES дешифрование");
}

// Тест 5: Тестирование смены ключа
void testKeyChange() {
    std::cout << "\n=== Тест 5: Тестирование смены ключа ===\n" << std::endl;
    
    auto cipher = std::make_unique<DESCipher>();
    Bytes plaintext = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    // Первый ключ
    Bytes key1 = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    cipher->setKey(key1);
    Bytes ciphertext1 = cipher->encryptBlock(plaintext);
    
    std::cout << "С ключом 1: ";
    printBytes(ciphertext1, "");
    
    // Второй ключ
    Bytes key2 = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    cipher->setKey(key2);
    Bytes ciphertext2 = cipher->encryptBlock(plaintext);
    
    std::cout << "С ключом 2: ";
    printBytes(ciphertext2, "");
    
    // Результаты должны быть разными для разных ключей
    if (ciphertext1 != ciphertext2) {
        std::cout << "✓ Разные ключи дают разные шифротексты" << std::endl;
    } else {
        std::cout << "✗ Разные ключи дали одинаковый результат!" << std::endl;
    }
}

// Тест 6: Тестирование граничных случаев
void testEdgeCases() {
    std::cout << "\n=== Тест 6: Тестирование граничных случаев ===\n" << std::endl;
    
    auto cipher = std::make_unique<DESCipher>();
    
    // Тест с нулевым ключом
    Bytes zeroKey(8, 0x00);
    Bytes allZeroKey(8, 0x00);
    Bytes plaintext = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    cipher->setKey(zeroKey);
    Bytes ciphertext = cipher->encryptBlock(plaintext);
    
    std::cout << "Нулевой ключ, нулевой текст -> ";
    printBytes(ciphertext, "");
    
    // Тест с ключом из всех единиц
    Bytes allOnesKey(8, 0xFF);
    cipher->setKey(allOnesKey);
    ciphertext = cipher->encryptBlock(plaintext);
    
    std::cout << "Ключ из 0xFF, нулевой текст -> ";
    printBytes(ciphertext, "");
    
    // Тест с чередующимися битами
    Bytes alternatingKey = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    Bytes alternatingText = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    
    cipher->setKey(alternatingKey);
    ciphertext = cipher->encryptBlock(alternatingText);
    
    std::cout << "Чередующиеся биты (ключ AA, текст 55) -> ";
    printBytes(ciphertext, "");
}

int main() {
    std::cout << "=================================================" << std::endl;
    std::cout << "     ТЕСТИРОВАНИЕ РЕАЛИЗАЦИИ DES (полное)       " << std::endl;
    std::cout << "=================================================" << std::endl;
    
    try {
        // Тестируем отдельные компоненты
        testKeyExpansion();
        testRoundFunction();
        
        // Тестируем сеть Фейстеля
        testFeistelNetwork();
        
        // Тестируем полный шифр
        testDESCipherWithKnownVector();
        testKeyChange();
        testEdgeCases();
        
        std::cout << "\n=================================================" << std::endl;
        std::cout << "            ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ                  " << std::endl;
        std::cout << "=================================================" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Ошибка во время тестирования: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}