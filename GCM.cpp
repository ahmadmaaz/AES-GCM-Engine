//
// Created by ahmad on 4/12/2025.
//


#include <iostream>
#include <vector>
#include <cmath>
#include <string>
#include <stdexcept>
#include "AES.cpp"
#include "Ghash.h"
#include <chrono>
#include <omp.h>

using namespace Utils;


class GCM {
private:
    ByteVector key;
    ByteVector IV;
    ByteVector AAD;

    void prepareCounter(ByteVector& counter, const ByteVector& IV) {
        // If IV is 96 bits, append 0x00000001 to form J0
        if (IV.size() == 12) {
            counter = IV;
            counter.push_back(0x00);
            counter.push_back(0x00);
            counter.push_back(0x00);
            counter.push_back(0x01);
        } else {
            throw invalid_argument("IV must be 96 bits (12 bytes) in this implementation.");
        }
    }



    void incrementCounter(ByteVector& counter) {
        for (int i = 15; i >= 12; --i) { // Last 4 bytes represent the counter
            if (++counter[i] != 0) {
                break; // Stop incrementing if no overflow
            }
        }
    }

    vector<ByteVector> GCTR(const ByteVector& ICB, const ByteVector& val) {
        vector<ByteVector> X = nest(val, 16);
        vector<ByteVector> res(X.size());

        // Precompute counters
        vector<ByteVector> counters(X.size());
        counters[0] = ICB;
        for (int i = 1; i < X.size(); ++i) {
            counters[i] = counters[i - 1];
            incrementCounter(counters[i]);
        }

        // Parallel encryption
        #pragma omp parallel
        {
            AES aes(key);
        #pragma omp for
            for (int i = 0; i < X.size(); ++i) {
                ByteVector encryptedBlock;
                aes.encrypt(counters[i],encryptedBlock);
                res[i] = xorF(encryptedBlock, X[i]);
            }
        }

        return res;
    }
    ByteVector gf128Multiply(const ByteVector &X, const ByteVector &H) {

        ByteVector result(16);
        Ghash::clmul_x86(result.data(), X.data(), H.data());
        return result;
    }
    void computeGF128Power(const ByteVector&H,int size,vector<ByteVector>& gf128Res){
        gf128Res.resize(size);
        gf128Res[0]=H;
        for(int i =1;i<size;i++){
            gf128Res[i] = gf128Multiply(gf128Res[i-1],H);
        }
    }

#pragma omp declare reduction(xorReduction : ByteVector : \
    omp_out = xorF(omp_out, omp_in)) initializer(omp_priv = ByteVector(16, 0x00))

    ByteVector GHASH(const ByteVector &val, const ByteVector &H) {
        // Split input into 16-byte blocks
        vector<ByteVector> X = nest(val, 16);
        int numBlocks = X.size();

        vector<ByteVector> gf128Res;

        this->computeGF128Power(H, numBlocks,gf128Res);

        ByteVector tag(16, 0x00);

        #pragma omp parallel for reduction(xorReduction : tag)
        for (int i = 0; i < numBlocks; ++i) {
            ByteVector hPower = gf128Res[numBlocks - i - 1];

            ByteVector term = gf128Multiply(X[i], hPower);

            tag = Utils::xorF(tag, term);
        }

        return tag;
    }
    ByteVector padC(const ByteVector& C, int u, int v, uint64_t sizeOfC, uint64_t sizeOfA) {
        size_t totalSize = AAD.size() + (v / 8) + C.size() + (u / 8) + 16;
        ByteVector res;
        res.reserve(totalSize);

        res.insert(res.end(), AAD.begin(), AAD.end());
        res.resize(res.size() + v / 8, 0x00);
        res.insert(res.end(), C.begin(), C.end());
        res.resize(res.size() + u / 8, 0x00);

        ByteVector lenA64 = encodeLength(sizeOfA);
        ByteVector lenC64 = encodeLength(sizeOfC);

        res.insert(res.end(), lenA64.begin(), lenA64.end());
        res.insert(res.end(), lenC64.begin(), lenC64.end());

        return res;
    }


    ByteVector encodeLength(uint64_t len) {
        ByteVector encoded(8, 0);
        for (int i = 7; i >= 0; --i) {
            encoded[i] = len & 0xFF;
            len >>= 8;
        }
        return encoded;
    }


public:


    pair<ByteVector, ByteVector> encrypt(const ByteVector key,  const ByteVector IV, const ByteVector AAD,ByteVector P) {
        this->AAD= AAD;
        this->IV = IV;
        this->key = key;

        AES aes(key);
        int sizeOfPlainText = P.size();

        ByteVector H;
        aes.encrypt(ByteVector(16, 0x00),H);

        ByteVector J0;
        prepareCounter(J0, this->IV);


        incrementCounter(J0);
        vector<ByteVector> C = GCTR(J0, P);
        ByteVector newC = flatten(C);
        while (sizeOfPlainText < newC.size()) {
            newC.pop_back();
            sizeOfPlainText++;
        }

        int sizeOfCinBits = newC.size() * 8;
        int sizeofAADinBits = AAD.size() * 8;

        int u = (128 * ceil((double) sizeOfCinBits / 128)) - sizeOfCinBits;
        int v = (128 * ceil((double) sizeofAADinBits / 128)) - sizeofAADinBits;


        ByteVector S = GHASH(padC(newC, u, v, sizeOfCinBits, sizeofAADinBits), H);


        prepareCounter(J0, this->IV);
        vector<ByteVector> T = GCTR(J0, S);
        ByteVector newT = flatten(T);


        return { newC, newT };
    }


};

int main(){
    omp_set_num_threads(12);
    // Key (16 bytes)
    ByteVector Key = {};

    for(int i =0;i<32;i++){
        Key.push_back(0x00);
    }
    ByteVector P ;
    for(int i =0;i<16;i++){
        P.push_back(0x00);
    }

    // IV (Initialization Vector, 12 bytes)
    ByteVector IV = {};
    for(int i =0;i<12;i++){
        IV.push_back(0x00);

    }

    // A (Associated Data, 20 bytes)
    ByteVector A = {

    };


    auto start_time = chrono::high_resolution_clock::now();

    GCM gcm;
    pair<ByteVector, ByteVector> res = gcm.encrypt(Key, IV, A,P);
    auto end_time = chrono::high_resolution_clock::now();

    cout << "Added Tag: " + bytesToHex(res.second) << "\n";
    chrono::duration<double> elapsed_time = end_time - start_time;

    cout << bytesToHex(res.first) << '\n';
    cout << "Elapsed Time: " << elapsed_time.count() << " seconds" << std::endl;
    return 0;
}