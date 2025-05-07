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
    string bytesToHex(const ByteVector & Block) {
        ostringstream hexStream;
        for (unsigned char byte : Block) {
            hexStream << hex << setw(2) << setfill('0') << static_cast<int>(byte);
        }
        return hexStream.str();
    }

    void xorF(const uint8_t* a, const uint8_t* b, uint8_t* out) {
        __m128i va = _mm_loadu_si128((const __m128i*)a);
        __m128i vb = _mm_loadu_si128((const __m128i*)b);
        __m128i vr = _mm_xor_si128(va, vb);
        _mm_storeu_si128((__m128i*)out, vr);
    }

    Block xorF(const Block &a, const Block &b) {
        Block result;
        xorF(a.data(), b.data(), result.data());
        return result;
    }

}