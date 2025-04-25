//
// Created by ahmad on 12/4/2024.
//

#include "Utils.h"
#include <string>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <emmintrin.h>
#include <cstring>

using namespace std;

namespace Utils{
    string bytesToHex(const Block & Block) {
        ostringstream hexStream;
        for (unsigned char byte : Block) {
            hexStream << hex << setw(2) << setfill('0') << static_cast<int>(byte);
        }
        return hexStream.str();
    }

    vector<Block> nest(const Block& plainText, int blockSize) {
        size_t total = plainText.size();
        size_t numBlocks = (total + blockSize - 1) / blockSize;

        vector<Block> blocks;
        blocks.reserve(numBlocks);  // ✅ Avoid reallocations

        for (size_t i = 0; i < total; i += blockSize) {
            auto begin = plainText.begin() + i;
            auto end = (i + blockSize < total) ? begin + blockSize : plainText.end();
            blocks.emplace_back(begin, end);  // ✅ Construct in-place
            blocks.back().resize(blockSize, 0x00); // ✅ Pad with 0x00 if needed
        }

        return blocks;
    }

    Block flatten(const vector<Block>& C) {
        size_t total = 0;
        for (const auto& block : C) total += block.size();

        Block result(total);
        uint8_t* ptr = result.data();

        for (const auto& block : C) {
            std::memcpy(ptr, block.data(), block.size());
            ptr += block.size();
        }

        return result;
    }

    void xorF(const uint8_t* a, const uint8_t* b, uint8_t* out) {
        __m128i va = _mm_loadu_si128((const __m128i*)a);
        __m128i vb = _mm_loadu_si128((const __m128i*)b);
        __m128i vr = _mm_xor_si128(va, vb);
        _mm_storeu_si128((__m128i*)out, vr);
    }

    Block xorF(const Block &a, const Block &b) {
        Block result;
        result.resize(16);
        xorF(a.data(), b.data(), result.data());
        return result;
    }

}