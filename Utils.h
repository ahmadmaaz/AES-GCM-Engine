//
// Created by ahmad on 12/4/2024.
//

#ifndef AES_PARALELIZED_UTILS_H
#define AES_PARALELIZED_UTILS_H

#include <vector>
#include <string>
#include <array>

using namespace std;

using Block  = std::array<uint8_t,16>;

template<size_t N>
using BlockN = std::array<uint8_t, N>;

using ByteVector= vector<uint8_t>;


namespace  Utils {
    string bytesToHex(const ByteVector& Block);
    void xorF(const uint8_t* a, const uint8_t* b, uint8_t* out);
    Block xorF(const Block &a, const Block &b);
};


#endif //AES_PARALELIZED_UTILS_H
