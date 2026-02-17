#include <cstdint>
#include <vector>

enum BitOrder
{
    BIG_END, // least significant first
    LITTLE_END // most significant first
};

enum BitCountingBase
{
    ZERO,
    ONE
};

std::vector<uint8_t> bit_Pbox_permutation
    (std::vector<uint8_t> const &value, 
     std::vector<size_t> const &p_box, 
     BitOrder bits_order, BitCountingBase counting_base);

