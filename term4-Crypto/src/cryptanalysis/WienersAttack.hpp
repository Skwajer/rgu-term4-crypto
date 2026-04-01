#include "../../math/Continued_fraction/ContinuedFractionService.hpp"

struct WienerAttackResult {
    bool success;
    BigInt d;                    // найденная секретная экспонента
    BigInt p;                    // первый простой множитель
    BigInt q;                    // второй простой множитель
    BigInt phi;                  // значение φ(N)
    std::string error_message;   // сообщение об ошибке, если атака не удалась
};


static WienerAttackResult wiener_attack(
    const BigInt& N,
    const BigInt& e)
{
    WienerAttackResult result;
    result.success = false;
    
    // Проверка входных данных
    if (N <= 1 || e <= 1) {
        result.error_message = "N and e must be greater than 1";
        return result;
    }
    
    // Получаем все подходящие дроби для e/N
    std::vector<BigInt> part_quotients = ContinuedFractionService::to_fraction(e, N);
    std::vector<ContinuedFractionService::Fraction>
    convergents = ContinuedFractionService::get_convergents(part_quotients);
    
    // Перебираем все подходящие дроби
    for (const auto& conv : convergents) 
    {
        const BigInt& k = conv.numerator;
        const BigInt& d_candidate = conv.denumenator;
        
        if (k <= 0) continue;
        
        BigInt ed_minus_1 = e * d_candidate - 1;
        if (ed_minus_1 % k != 0) continue;
        
        BigInt phi_candidate = ed_minus_1 / k;
        
        if (phi_candidate <= 0 || phi_candidate >= N) continue;
        
        BigInt b = N - phi_candidate + 1;
        BigInt discriminant = b * b - 4 * N;
        
        if (discriminant < 0) continue;
        
        BigInt sqrt_disc = boost::multiprecision::sqrt(discriminant);
        if (sqrt_disc * sqrt_disc != discriminant) continue;
        
        BigInt p = (b - sqrt_disc) / 2;
        BigInt q = (b + sqrt_disc) / 2;
        
        if (p <= 0 || q <= 0) continue;
        
        if (p * q != N) continue;
        
        BigInt phi_actual = (p - 1) * (q - 1);
        if ((e * d_candidate) % phi_actual != 1) continue;
        
        result.success = true;
        result.d = d_candidate;
        result.p = p;
        result.q = q;
        result.phi = phi_actual;
        return result;
    }
    
    result.error_message = "Wiener attack failed: no convergent produced valid factorization. "
                           "This likely means d >= (1/3)*N^(1/4), so the attack condition is not satisfied.";
    return result;
}