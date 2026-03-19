#include <gtest/gtest.h>
#include <memory>
#include <iostream>
#include "../math/fermat_primality_test/FermatPrimalityTest.hpp"

class FermatPrimalityTestTest : public ::testing::Test {
protected:
    void SetUp() override {
        test = std::make_unique<FermatPrimalityTest>();
    }
    
    std::unique_ptr<FermatPrimalityTest> test;
    double prob = 0.85;
};




TEST_F(FermatPrimalityTestTest, CheckThisNumber) {
    BigInt n("35742549198872617291353508656626642567");
    
    std::cout << "\n=== Проверка числа ===" << std::endl;
    std::cout << "Число: " << n << std::endl;
    
    bool result = test->is_prime(n, 0.99);
    std::cout << "Результат теста Ферма: " << (result ? "ПРОСТОЕ" : "СОСТАВНОЕ") << std::endl;
    
    std::cout << "\nПроверка малых делителей:" << std::endl;
    std::vector<int> small_primes = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    
    for (int p : small_primes) {
        if (n % p == 0) {
            std::cout << "Делится на " << p << "!" << std::endl;
            std::cout << n << " / " << p << " = " << n / p << std::endl;
            break;
        }
    }
}

TEST_F(FermatPrimalityTestTest, CheckBigNumber) {
    BigInt n("359334085968622831041960188598043661065388726959079837");
    
    std::cout << "digit: " << n << std::endl;
    
    bool result = test->is_prime(n, 0.999);
    std::cout << "Результат теста Ферма: " << (result ? "ПРОСТОЕ" : "СОСТАВНОЕ") << std::endl;
    
    std::vector<int> small_primes = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47};
    
    bool found = false;
    for (int p : small_primes) {
        if (n % p == 0) {
            std::cout << "Делится на " << p << "!" << std::endl;
            std::cout << n << " / " << p << " = " << n / p << std::endl;
            found = true;
            break;
        }
    }
    
    if (!found) {
        std::cout << "Не найдено малых делителей < 50" << std::endl;
    }
}