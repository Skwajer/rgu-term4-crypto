#include "Pbox_permutation.hpp"
#include <cstddef>
#include <iostream>


std::vector<uint8_t> bit_Pbox_permutation
    (std::vector<uint8_t> const &value, 
     std::vector<size_t> const &p_box, 
     BitOrder bits_order, BitCountingBase counting_base)
{
    if (p_box.empty())
    return {};

  size_t out_size = (p_box.size() + 7) / 8;
  std::vector<uint8_t> out(out_size, 0);

  bool index_base_one = counting_base == BitCountingBase::ONE;
  bool big_endian = bits_order == BitOrder::BIG_END;
  size_t total_bits = value.size() * 8;

  for (size_t i = 0; i < p_box.size(); i++) {
    size_t index = p_box[i];

    if (index_base_one) {
      index--;
    }

    if (!big_endian) {
      index = total_bits - 1 - index;
    }

    uint8_t val = 0;
    if (index < total_bits) {
      val = (value[index / 8] >> (7 - (index % 8))) & 1;
    }

    out[i / 8] |= val << (7 - (i % 8));
  }

  return out;
}