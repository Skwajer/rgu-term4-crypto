#include "Sbox_substitution.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <vector>
  
std::vector<uint8_t>
substitute(const std::vector<uint8_t> &bits,
           const std::unordered_map<uint8_t, uint8_t> &s_block,
           size_t block_size_in, size_t block_size_out)
{
    if (bits.empty() || s_block.empty() || !block_size_out)
    {
        return {};
    }
    if (!block_size_in)
    {
        return bits;
    }
    size_t max_s_box_block_size = 8;
    if (block_size_in > max_s_box_block_size || block_size_out > max_s_box_block_size)
    {
        throw std::invalid_argument("block_size_in cannot be greater than 8 for uint8_t S_box");
    }

    size_t total_bits_in = bits.size() * 8;
    size_t total_blocks_in = total_bits_in / block_size_in;
    size_t bits_remaining_in = total_bits_in % block_size_in;
    size_t total_bits_out = total_blocks_in * block_size_out + bits_remaining_in;
    size_t total_blocks_out = (total_bits_out + 7) / 8;
    std::vector<uint8_t> result(total_blocks_out, 0);

    auto curr_byte_id = 0;
    auto bit_pos_in_byte = 0;
    auto curr_out_byte_id = 0;
    auto bit_pos_out_byte = 0;
    auto curr_key = 0;

    for (auto in_block_id = 0; in_block_id < total_blocks_in; in_block_id++)
    {
        if (bit_pos_in_byte == 8) 
        {
            bit_pos_in_byte = 0;
            curr_byte_id++;
        }
        if (bit_pos_in_byte + block_size_in <= 8)
        {
            curr_key = (bits[curr_byte_id] >> (8 - block_size_in - bit_pos_in_byte)) 
                        & ((1 << block_size_in) - 1);
            bit_pos_in_byte += block_size_in;
        }

        else //if key devided between adjacent bytes
        {

            size_t bits_from_current = 8 - bit_pos_in_byte;
            size_t bits_from_next = block_size_in - bits_from_current;        
            uint8_t current_part = bits[curr_byte_id] & ((1 << bits_from_current) - 1);        
            curr_byte_id++;
            bit_pos_in_byte = 0;
            uint8_t next_part = bits[curr_byte_id] >> (8 - bits_from_next);
            curr_key = (current_part << bits_from_next) | next_part;
            bit_pos_in_byte = bits_from_next;
        }

        auto out_bits = s_block.at(curr_key) & ((1 << block_size_out) - 1);

        if (bit_pos_out_byte == 8)
            {
                bit_pos_out_byte = 0;
                curr_out_byte_id++;
            }
        if (bit_pos_out_byte + block_size_out <= 8)
        {
            result[curr_out_byte_id] |= out_bits << (8 - block_size_out - bit_pos_out_byte);
            bit_pos_out_byte += block_size_out;
        }
        else 
        {
            size_t total_bits_from_current = 8 - bit_pos_out_byte;
            size_t total_bits_from_next = block_size_out - total_bits_from_current;
            auto current_part = out_bits >> total_bits_from_next;
            result[curr_out_byte_id] |= current_part << (8 - bit_pos_out_byte - total_bits_from_current);
            curr_out_byte_id++;
            bit_pos_out_byte = 0;
            auto next_part = out_bits & ((1 << total_bits_from_next) - 1);
            result[curr_out_byte_id] |= next_part << (8 - total_bits_from_next /* - bit_pos_out_byte == 0*/);
            bit_pos_out_byte = total_bits_from_next; 
        }
    }

    if (bits_remaining_in > 0)
        {
            size_t base_bit = total_blocks_in * block_size_in;
            
            for (size_t b = 0; b < bits_remaining_in; ++b)
            {
                size_t in_byte_idx = (base_bit + b) / 8;
                size_t in_bit_idx = 7 - ((base_bit + b) % 8);
                uint8_t bit_val = (bits[in_byte_idx] >> in_bit_idx) & 1;

                size_t out_byte_idx = (total_blocks_in * block_size_out + b) / 8;
                size_t out_bit_idx = 7 - ((total_blocks_in * block_size_out + b) % 8);
                
                result[out_byte_idx] |= bit_val << out_bit_idx;
            }
        }
    return result;
}
