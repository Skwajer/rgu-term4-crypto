#include "ContinuedFractionService.hpp"
#include <algorithm>
#include <stdexcept>
#include <vector>

std::vector<BigInt> 
ContinuedFractionService::to_fraction(
    BigInt const &num, BigInt const &den)
{
    if (num < 0)
    {
        throw std::invalid_argument("numerator must be non-negative");
    }
    if (den <= 0)
    {
        throw std::invalid_argument("denominator must be positive");
    }
    std::vector<BigInt> result;
    BigInt curr_num = num, curr_den = den;
    BigInt r;
    while (curr_den != 0)
    {
        result.push_back(curr_num / curr_den);
        r = curr_num % curr_den;
        curr_num = curr_den;
        curr_den = r;
    }
    return result;
}


ContinuedFractionService::Fraction 
ContinuedFractionService::from_fraction(
    std::vector<BigInt> const &part_quotients)
{
    if (part_quotients.empty())
    {
        return {0, 1};
    }
    BigInt curr_num = part_quotients.back();
    BigInt curr_den = 1;
    for (auto i = part_quotients.size() - 2; i > 0; i--)
    {
        curr_num = curr_num * part_quotients[i] + curr_den;
        curr_den = curr_num;
    }
    return {curr_num, curr_den};
}


std::vector<ContinuedFractionService::Fraction> 
ContinuedFractionService::get_convergents(
    std::vector<BigInt> const &part_quotients)
{
    std::vector<ContinuedFractionService::Fraction> result;
    if (part_quotients.empty())
    {
        result.push_back({1, 0});
    }
    BigInt p_prev = 1, p_curr = part_quotients[0];
    BigInt q_prev = 0, q_curr = 1;
    result.push_back({p_curr, q_curr});
    for (int i = 0; i < part_quotients.size(); i++)
    {
        BigInt p_new = part_quotients[i] * p_curr + p_prev;
        BigInt q_new = part_quotients[i] * q_curr + q_prev;
        result.push_back({p_new, q_new});
        p_prev = p_curr;
        q_prev = q_curr;
        p_curr = p_new;
        q_curr = q_new;
    }
    return result;
}


std::vector<int> 
ContinuedFractionService::to_Calkin_Wilf_path(
    BigInt const &num, BigInt const &den)
{
    if (num <= 0 || den <= 0)
    {
        throw std::invalid_argument("numerator and denominator must be positive");
    }
    std::vector<int> result;
    BigInt num_curr = num, den_curr = den;
    while (num_curr != 1 || den_curr != 1)
    {
        if (num_curr > den_curr)
        {
            result.push_back(0);
            num_curr -= den_curr;
        }
        else
        {
            result.push_back(1);
            den_curr -= num_curr;
        }
    }
    std::reverse(result.begin(), result.end());
    return result;
}


std::vector<int> 
ContinuedFractionService::to_Stern_Brocot_path(
    BigInt const &num, BigInt const &den)
{
    if (num <= 0 || den <= 0)
    {
        throw std::invalid_argument("numerator and denominator must be positive");
    }
    std::vector<int> result;
    BigInt num_l = 0, den_l = 1;
    BigInt num_r = 1, den_r = 0;
    while (true)
    {
        BigInt num_m = num_l + num_r;
        BigInt den_m = den_l + den_r;
        if (num * den_m == den * num_m)
        {
            break;
        }
        if (num * den_m < den * num_m)
        {
            result.push_back(0);
            num_r = num_m;
            den_r = den_m;
        }
        else
        {
            result.push_back(1);
            num_l = num_m;
            den_l = den_m;
        }
    }
    return result;
}


ContinuedFractionService::Fraction 
ContinuedFractionService::from_Calkin_Wilf_path(
    std::vector<int> const &path)
{
    Fraction result{1, 1};
    for (int i = 0; i < path.size(); i++)
    {
        if (!path[i])
        {
            result.denumenator += result.numerator;
        }
        else 
        {
            result.numerator += result.denumenator;
        }
    }
    return result;
}


ContinuedFractionService::Fraction 
ContinuedFractionService::from_Stern_Brocot_path(
    std::vector<int> const &path)
{
    BigInt num_l = 0, den_l = 1;
    BigInt num_r = 1, den_r = 0;
    for (int i = 0; i < path.size(); i++)
    {
        BigInt num_m = num_l + num_r;
        BigInt den_m = den_l + den_r;
        if (!path[i])
        {
            num_r = num_m;
            den_r = den_m;
        }
        else 
        {
            num_l = num_m;
            den_l = den_m;
        }
    }
    return {num_l + num_r, den_l + den_r};
}


std::vector<ContinuedFractionService::Fraction> 
ContinuedFractionService::get_convergents_from_Stern_Brocot_path(
    std::vector<int> const &path)
{
    std::vector<ContinuedFractionService::Fraction> result;
    BigInt num_l = 0, den_l = 1;
    BigInt num_r = 1, den_r = 0;
    for (int i = 0; i < path.size(); i++)
    {
        BigInt num_m = num_l + num_r;
        BigInt den_m = den_l + den_r;
        result.push_back({num_m, den_m});
        if (!path[i])
        {
            num_r = num_m;
            den_r = den_m;
        }
        else 
        {
            num_l = num_m;
            den_l = den_m;
        }
    }
    return result;
}