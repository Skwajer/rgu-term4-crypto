#include "padding.hpp"
#include <stdexcept>

namespace crypto 
{

    static void validate_block_size(size_t block_size)
    {
        if (block_size == 0)
        {
            throw std::invalid_argument("block size can't be zero");
        }
    }

    static void validate_data(Bytes const &data, size_t block_size)
    {
        if ((data.size() % block_size) != 0)
        {
            throw std::invalid_argument("data cannot be empty or multiple of a block");
        }
    }

    Bytes ZerosPadding::apply(Bytes const &data, size_t block_size) const 
    {
        validate_block_size(block_size);
        auto remainder = data.size() % block_size;
        if (remainder == 0)
        {
            return data;
        }
        auto total_remaining_bytes = block_size - remainder;

        Bytes result = data;
        result.insert(result.end(), total_remaining_bytes, 0x00);
        return result;
    }

    Bytes ZerosPadding::remove(Bytes const &data, size_t block_size) const 
    {
        validate_block_size(block_size);
        validate_data(data, block_size);
        auto end = data.size() -1;
        while (end + 1 > 0 && (data[end] == 0))
        {
            end--;
        }
        return Bytes(data.begin(), data.begin() + end + 1);
    }

    Bytes AnsiX923Padding::apply(const Bytes &data, size_t block_size) const
    {
        validate_block_size(block_size);
        auto remainder = data.size() % block_size;
        auto total_remaining_bytes = block_size - remainder;
        total_remaining_bytes = (total_remaining_bytes == 0 ? block_size : total_remaining_bytes);
        auto result = data;
        result.insert(result.end(), total_remaining_bytes - 1, 0x00);
        result.emplace_back(static_cast<Byte>(total_remaining_bytes));
        return result;
    }
    Bytes AnsiX923Padding::remove(const Bytes &data, size_t block_size) const
    {
        validate_block_size(block_size);
        validate_data(data, block_size);
        auto padded_zeros_count = data.back();

        for (auto i = data.size() - padded_zeros_count; i < data.size() - 1; i++)
        {
            if (data[i] != 0x00) {throw std::invalid_argument("data was padded incorrectly according to ANSI X923 or not padded at all");}
        }
        return Bytes(data.begin(), data.end() - padded_zeros_count);
    }
}