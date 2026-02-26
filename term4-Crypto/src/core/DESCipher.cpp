#include "DESCipher.hpp"
#include <algorithm>
#include <bitset>
#include <cstring>
#include <iostream>
#include <stdint.h>

namespace crypto {
    // Инициализация статических констант для DES
    const std::vector<int> DESCipher::IP = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    
    const std::vector<int> DESCipher::FP = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };
    
    // Инициализация констант для DESKeyExpansion
    const std::vector<int> DESCipher::DESKeyExpansion::PC1 = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };
    
    const std::vector<int> DESCipher::DESKeyExpansion::PC2 = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };
    
    const std::vector<int> DESCipher::DESKeyExpansion::SHIFT_SCHEDULE = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };
    
    // Инициализация констант для DESRoundFunction
    const std::vector<int> DESCipher::DESRoundFunction::E = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };
    
    const std::vector<int> DESCipher::DESRoundFunction::P = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };
    
    // S-Boxes для DES
    const std::vector<std::vector<ByteArray>> DESCipher::DESRoundFunction::S_BOXES = []() {
        std::vector<std::vector<ByteArray>> boxes(8);
        
        // S1
        boxes[0] = {
            {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
            {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
            {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
            {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
        };
        
        // S2
        boxes[1] = {
            {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
            {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
            {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
            {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
        };
        
        // S3
        boxes[2] = {
            {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
            {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
            {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
            {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
        };
        
        // S4
        boxes[3] = {
            {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
            {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
            {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
            {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
        };
        
        // S5
        boxes[4] = {
            {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
            {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
            {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
            {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
        };
        
        // S6
        boxes[5] = {
            {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
            {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
            {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
            {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
        };
        
        // S7
        boxes[6] = {
            {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
            {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
            {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
            {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
        };
        
        // S8
        boxes[7] = {
            {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
            {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
            {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
            {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
        };
        
        return boxes;
    }();
    
    // Реализация DESKeyExpansion
    std::vector<uint64_t> DESCipher::DESKeyExpansion::generateRoundKeys(const std::vector<uint8_t>& key) {
        std::vector<uint64_t> roundKeys(16);
        
        // Преобразуем ключ в 64-битное число
        uint64_t key64 = 0;
        for (int i = 0; i < 8; i++) {
            key64 = (key64 << 8) | key[i];
        }
        
        // Применяем PC1 для получения 56-битного ключа
        uint64_t permutedKey = 0;
        for (int i = 0; i < 56; i++) {
            int bitPos = PC1[i] - 1;
            uint64_t bit = (key64 >> (63 - bitPos)) & 1;
            permutedKey |= (bit << (55 - i));
        }
        
        // Разделяем на C и D (по 28 бит)
        uint32_t C = (permutedKey >> 28) & 0x0FFFFFFF;
        uint32_t D = permutedKey & 0x0FFFFFFF;
        
        // Генерируем 16 раундовых ключей
        for (int round = 0; round < 16; round++) {
            // Циклический сдвиг влево
            int shift = SHIFT_SCHEDULE[round];
            
            // Сдвигаем C
            uint32_t mask = (1 << (28 - shift)) - 1;
            uint32_t carry = (C >> (28 - shift)) & ((1 << shift) - 1);
            C = ((C & mask) << shift) | carry;
            
            // Сдвигаем D
            carry = (D >> (28 - shift)) & ((1 << shift) - 1);
            D = ((D & mask) << shift) | carry;
            
            // Объединяем C и D в 56-битный ключ
            uint64_t combined = ((uint64_t)C << 28) | D;
            
            // Применяем PC2 для получения 48-битного раундового ключа
            uint64_t roundKey = 0;
            for (int i = 0; i < 48; i++) {
                int bitPos = PC2[i] - 1;
                uint64_t bit = (combined >> (55 - bitPos)) & 1;
                roundKey |= (bit << (47 - i));
            }
            
            roundKeys[round] = roundKey;
        }
        
        return roundKeys;
    }
    
    // Реализация DESRoundFunction
    uint32_t DESCipher::DESRoundFunction::f(uint32_t R, uint64_t K) {
        // Расширение E с 32 до 48 бит
        uint64_t expandedR = 0;
        for (int i = 0; i < 48; i++) {
            int bitPos = E[i] - 1;
            uint64_t bit = (R >> (31 - bitPos)) & 1;
            expandedR |= (bit << (47 - i));
        }
        
        // XOR с раундовым ключом
        expandedR ^= K;
        
        // S-Box подстановка (48 -> 32 бит)
        uint32_t sBoxOutput = 0;
        for (int i = 0; i < 8; i++) {
            // Берем 6 бит для текущего S-Box
            int sixBits = (expandedR >> (42 - i * 6)) & 0x3F;
            
            // Определяем строку (биты 0 и 5) и столбец (биты 1-4)
            int row = ((sixBits >> 5) & 1) * 2 + (sixBits & 1);
            int col = (sixBits >> 1) & 0x0F;
            
            // Получаем значение из S-Box
            int sValue = S_BOXES[i][row][col];
            
            // Добавляем в результат (4 бита)
            sBoxOutput = (sBoxOutput << 4) | sValue;
        }
        
        // P-перестановка
        uint32_t result = 0;
        for (int i = 0; i < 32; i++) {
            int bitPos = P[i] - 1;
            uint32_t bit = (sBoxOutput >> (31 - bitPos)) & 1;
            result |= (bit << (31 - i));
        }
        
        return result;
    }
    
    // Реализация DESCipher
    DESCipher::DESCipher() 
        : FeistelCipher(std::make_unique<FeistelNetwork>(
              std::make_unique<DESRoundFunction>(),
              std::make_unique<DESKeyExpansion>(),
              16)) {}
    
    uint64_t DESCipher::permute(uint64_t block, const std::vector<int>& table) {
        uint64_t result = 0;
        for (size_t i = 0; i < table.size(); i++) {
            int bitPos = table[i] - 1;
            uint64_t bit = (block >> (63 - bitPos)) & 1;
            result |= (bit << (63 - i));
        }
        return result;
    }
    
    void DESCipher::preEncrypt(std::vector<uint8_t>& block) {
        if (block.size() != 8) return;
        
        // Преобразуем блок в 64-битное число
        uint64_t block64 = 0;
        for (int i = 0; i < 8; i++) {
            block64 = (block64 << 8) | block[i];
        }
        
        // Применяем начальную перестановку IP
        block64 = permute(block64, IP);
        
        // Преобразуем обратно в массив байт
        for (int i = 7; i >= 0; i--) {
            block[i] = block64 & 0xFF;
            block64 >>= 8;
        }
    }
    
    void DESCipher::postEncrypt(std::vector<uint8_t>& block) {
        if (block.size() != 8) return;
        
        // Преобразуем блок в 64-битное число
        uint64_t block64 = 0;
        for (int i = 0; i < 8; i++) {
            block64 = (block64 << 8) | block[i];
        }
        
        // Применяем конечную перестановку FP (обратную к IP)
        block64 = permute(block64, FP);
        
        // Преобразуем обратно в массив байт
        for (int i = 7; i >= 0; i--) {
            block[i] = block64 & 0xFF;
            block64 >>= 8;
        }
    }
    
    void DESCipher::preDecrypt(std::vector<uint8_t>& block) {
        // Для дешифрования сначала применяем FP (обратную к IP)
        if (block.size() != 8) return;
        
        uint64_t block64 = 0;
        for (int i = 0; i < 8; i++) {
            block64 = (block64 << 8) | block[i];
        }
        
        block64 = permute(block64, FP);
        
        for (int i = 7; i >= 0; i--) {
            block[i] = block64 & 0xFF;
            block64 >>= 8;
        }
    }
    
    void DESCipher::postDecrypt(std::vector<uint8_t>& block) {
        // Для дешифрования после всех раундов применяем IP
        if (block.size() != 8) return;
        
        uint64_t block64 = 0;
        for (int i = 0; i < 8; i++) {
            block64 = (block64 << 8) | block[i];
        }
        
        block64 = permute(block64, IP);
        
        for (int i = 7; i >= 0; i--) {
            block[i] = block64 & 0xFF;
            block64 >>= 8;
        }
    }
}