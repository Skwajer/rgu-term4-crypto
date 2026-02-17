#include "Pbox_permutation.hpp"
#include <cstddef>


std::vector<uint8_t> bit_Pbox_permutation
    (std::vector<uint8_t> const &value, 
     std::vector<size_t> const &p_box, 
     BitOrder bits_order, BitCountingBase counting_base)
{
    if (value.empty() || p_box.empty())
    {
        return {};
    }
    auto bits_count = value.size() * 8;
    bool is_big_end_order = bits_order == BitOrder::BIG_END;
    bool is_zero_cnt_base = counting_base == BitCountingBase::ZERO;
    std::vector<uint8_t> result((p_box.size() / 8), 0);

    for (size_t i = 0; i < p_box.size(); i++)
    {
        auto index = p_box[i];
        if (!is_zero_cnt_base)
        {
            --index;
        }
        if (!is_big_end_order)
        {
            index = bits_count - index - 1;
        }

        auto res_bit = 0;
        if (bits_count > index)
        {
            res_bit = (value[index / 8] >> (7 - (index % 8))) & 1;
        }
        result[i / 8] |= res_bit << (7 - (index % 8));
    }
    return result;
}