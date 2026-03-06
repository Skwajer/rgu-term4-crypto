#include "modes.hpp"
#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <thread>
#include <vector>

namespace crypto 
{

    static std::vector<std::pair<size_t, size_t>> split_blocks_between_threads(size_t total_blocks, size_t total_threads)
    {
        std::vector<std::pair<size_t, size_t>> result;
        result.reserve(total_threads);
        auto blocks_per_thread = total_blocks / total_threads;
        auto remaining_blocks = total_blocks % total_threads;

        size_t current_block;
        for (auto t = 0; t < total_threads; t++)
        {
            auto blocks_of_current_thread = blocks_per_thread + (t < remaining_blocks ? 1 : 0);

            auto start = current_block;
            auto end = current_block + blocks_of_current_thread;
            current_block = end;
            result.push_back({start, end});
        }
        return result;
    }

static void process(ISymmetricCipher &cipher, const Bytes &input,
                    Bytes &output, size_t threads, bool encrypting)
{
    auto block_size = cipher.block_size();
    auto total_input_bytes = input.size();
    if (total_input_bytes % block_size != 0)
    {
        throw std::invalid_argument("input data must be padded to cipher block size");
    }
    auto total_blocks = total_input_bytes / block_size;
    
    auto threads_ranges = split_blocks_between_threads(total_blocks, threads);
    std::vector<std::thread> workers;

    for (auto [start, end] : threads_ranges)
    {
        workers.emplace_back([&, start, end] ()
        {
            for (auto current_block = start; current_block < end; current_block++)
            {
                Bytes block(input.begin() + current_block*block_size, input.begin() + current_block*block_size + block_size);
                Bytes result = (encrypting ? cipher.encryptBlock(block) : cipher.decryptBlock(block));
                std::copy(result.begin(), result.end(), output);
            }
        });
    }

    for (auto &t : workers)
    {
        t.join();
    }
}




void ECB::encrypt(ISymmetricCipher &cipher, const Bytes &input,
            Bytes &output, size_t threads)
{
    
}
}