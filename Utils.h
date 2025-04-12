//
// Created by ahmad on 12/4/2024.
//

#ifndef AES_PARALELIZED_UTILS_H
#define AES_PARALELIZED_UTILS_H

#include <vector>
#include <string>
using namespace std;
typedef vector<uint8_t> ByteVector;


namespace  Utils {
    string bytesToHex(const ByteVector& byteVector);
    ByteVector xorF(const ByteVector &A, const ByteVector &B);
    vector<ByteVector> nest(const ByteVector& plainText, int size);
    ByteVector flatten(const vector<ByteVector>& C);
};


#endif //AES_PARALELIZED_UTILS_H
