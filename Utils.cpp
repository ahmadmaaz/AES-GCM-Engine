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
using namespace std;

namespace Utils{
    string bytesToHex(const ByteVector & byteVector) {
        ostringstream hexStream;
        for (unsigned char byte : byteVector) {
            hexStream << hex << setw(2) << setfill('0') << static_cast<int>(byte);
        }
        return hexStream.str();
    }


    vector<ByteVector> nest(const ByteVector& plainText,int size) {
        vector<ByteVector> blocks;

        for (size_t i = 0; i < plainText.size(); i += size) {
            ByteVector block(size, 0x00);

            for (size_t j = 0; j < size && (i + j) < plainText.size(); ++j) {
                block[j] = plainText[i + j];
            }
            blocks.push_back(block);
        }
        while(size==4 && blocks.size()!=4){
            blocks.push_back(ByteVector(0x00,4));
        }
        return blocks;
    }

    ByteVector flatten(const vector<ByteVector>& C) {
        ByteVector result;

        for (const auto& block : C) {
            result.insert(result.end(), block.begin(), block.end());
        }

        return result;
    }
    ByteVector xorF(const ByteVector &a, const ByteVector &b) {
        size_t len = a.size();
        if (len != b.size()) throw std::invalid_argument("Vectors must be the same size");

        ByteVector result(len);

        size_t i = 0;
        size_t blocks = len / 16;

        for (; i < blocks * 16; i += 16) {
            __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&a[i]));
            __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&b[i]));
            __m128i vr = _mm_xor_si128(va, vb);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(&result[i]), vr);
        }

        uint8_t* resPtr = result.data() + i;
        const uint8_t* aPtr = a.data() + i;
        const uint8_t* bPtr = b.data() + i;

        for (; i < len; ++i) {
            *resPtr++ = *aPtr++ ^ *bPtr++;
        }

        return result;
    }
}