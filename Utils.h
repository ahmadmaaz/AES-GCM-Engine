//
// Created by ahmad on 12/4/2024.
//

#ifndef AES_PARALELIZED_UTILS_H
#define AES_PARALELIZED_UTILS_H

#include <vector>
#include <string>
#include <array>

using namespace std;
using Block  = std::vector<uint8_t>;


namespace  Utils {
    string bytesToHex(const Block& Block);
    void xorF(const uint8_t* a, const uint8_t* b, uint8_t* out);
    vector<Block> nest(const Block& plainText, int size);
    Block flatten(const vector<Block>& C);
    Block xorF(const Block &a, const Block &b);
};


#endif //AES_PARALELIZED_UTILS_H
