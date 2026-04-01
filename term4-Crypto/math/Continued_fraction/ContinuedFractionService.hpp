#pragma once
#include "../NumberTheoryService.hpp"
#include <vector>

class ContinuedFractionService
{
public:
    struct Fraction 
    {
        BigInt numerator;
        BigInt denumenator;
    };
    static std::vector<BigInt> to_fraction(BigInt const &num, BigInt const &den);
    static Fraction from_fraction(std::vector<BigInt> const &part_quotients);
    static std::vector<Fraction> get_convergents(std::vector<BigInt> const &part_quotients);
    static std::vector<int> to_Calkin_Wilf_path(BigInt const &num, BigInt const &den);
    static std::vector<int> to_Stern_Brocot_path(BigInt const &num, BigInt const &den);
    static Fraction from_Calkin_Wilf_path(std::vector<int> const &path);
    static Fraction from_Stern_Brocot_path(std::vector<int> const &path);
    static std::vector<Fraction> get_convergents_from_Stern_Brocot_path(std::vector<int> const &path);
    
};