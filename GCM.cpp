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
#include <functional>
#include <immintrin.h>
using namespace Utils;


class GCM {
private:
    BlockN<32> key;
    BlockN<12> IV;
    BlockN<20> AAD;

    __attribute__((always_inline)) inline
    void prepareCounter(Block& counter, const BlockN<12>& IV) {
        reinterpret_cast<uint64_t*>(counter.data())[0] =
                reinterpret_cast<const uint64_t*>(IV.data())[0];
        reinterpret_cast<uint64_t*>(counter.data())[1] =
                reinterpret_cast<const uint64_t*>(IV.data())[1];

        // Set counter (big-endian 0x00000001)
        reinterpret_cast<uint32_t*>(counter.data())[3] = 0x01000000;
    }



    void incrementCounter(Block& counter) {
        uint8_t* p = counter.data() + 15;
        while (++(*p--) == 0 && p >= counter.data() + 12) {}
    }

    ByteVector GCTR(const Block& ICB, const ByteVector& val) {
        int nmbOfBlocks = round(val.size()/16);
        ByteVector res(val.size());

        // Precompute counters
        vector<Block> counters(nmbOfBlocks);
        counters[0] = ICB;
        for (int i = 1; i < nmbOfBlocks; ++i) {
            counters[i] = counters[i - 1];
            incrementCounter(counters[i]);
        }


        // Parallel encryption
        AES aes(key);

        #pragma omp parallel
        {
        #pragma omp for
            for (int i = 0; i < nmbOfBlocks; ++i) {
                Block encryptedBlock;
                aes.encrypt(counters[i],encryptedBlock);

                xorF(encryptedBlock.data(), val.data() + (i*16), res.data()+ (i*16));
            }
        }

        return res;
    }
#pragma omp declare reduction(xorReduction : Block : \
    omp_out = xorF(omp_out, omp_in)) initializer(omp_priv = Block())

    Block GHASH(const ByteVector &val, const Block &H) {
        // Split input into 16-byte blocks
        int numBlocks = round((float)val.size()/16);

        vector<Block> gf128Res;
        this->computeGF128Power(H, numBlocks,gf128Res);
//        this->computeGF128Power(H, numBlocks,gf128Res);

        Block tag{};

        #pragma omp parallel for reduction(xorReduction : tag)
        for (int i = 0; i < numBlocks; ++i) {
            Block hPower = gf128Res[numBlocks - i - 1];

            Block term{};
            gf128Multiply(val.data() +(i*16), hPower.data(),term.data());

            xorF(tag.data(),term.data(),tag.data());
        }

        return tag;
    }

    void gf128Multiply(const uint8_t* X, const uint8_t* H, const uint8_t* output) {

        Ghash::clmul_x86(output, X, H);
    }
    void computeGF128Power(const Block&H,int size,vector<Block>& gf128Res){
        gf128Res.resize(size);
        gf128Res[0]=H;
        #pragma omp for
        for(int i =1;i<size;i++){
            gf128Multiply(gf128Res[i-1].data(),H.data(),gf128Res[i].data());
        }
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


    pair<ByteVector, ByteVector> encrypt(const BlockN<32>& key,  const BlockN<12>& IV, const BlockN<20>& AAD,const ByteVector& P) {
        this->AAD= AAD;
        this->IV = IV;
        this->key = key;

        AES aes(key);
        int sizeOfPlainText = P.size();

        Block H{};
        aes.encrypt(Block(),H);

        Block J0{};
        prepareCounter(J0, this->IV);
        incrementCounter(J0);

        ByteVector C = GCTR(J0, P);

//
//        while (sizeOfPlainText < newC.size()) {
//            newC.pop_back();
//            sizeOfPlainText++;
//        }

        int sizeOfCinBits = C.size() * 8;
        int sizeofAADinBits = AAD.size() * 8;

        int u = (128 * ceil((double) sizeOfCinBits / 128)) - sizeOfCinBits;
        int v = (128 * ceil((double) sizeofAADinBits / 128)) - sizeofAADinBits;


        Block S = GHASH(padC(C, u, v, sizeOfCinBits, sizeofAADinBits), H);

        ByteVector T = GCTR(J0, ByteVector(S.begin(), S.end()));


        return { C, T };
    }


};

int main(){
    omp_set_num_threads(2);

    // Key (16 bytes)
    BlockN<32> Key{};

    for(int i =0;i<32;i++){
        Key[i]=(0x00);
    }
    ByteVector P ;
    long long N = 256 * 1000 ;
    for(int i =0;i<N;i++){
        P.push_back(0x00);
    }

    // IV (Initialization Vector, 12 bytes)
    BlockN<12> IV{} ;
    for(int i =0;i<12;i++){
        IV[i]=(0x00);

    }

    // A (Associated Data, 20 bytes)
    BlockN<20> A{};


    auto start_time = chrono::high_resolution_clock::now();

    GCM gcm;
    pair<ByteVector , ByteVector> res = gcm.encrypt(Key, IV, A,P);
    auto end_time = chrono::high_resolution_clock::now();

    chrono::duration<double> elapsed_time = end_time - start_time;

    cout << "Added Tag: " + bytesToHex(res.second) << "\n";

    cout << "Elapsed Time: " << elapsed_time.count() << " seconds" << std::endl;

    double dataSizeBytes = N;
    double elapsedSeconds = elapsed_time.count();
    double throughputMBps = dataSizeBytes / (1024.0 * 1024.0) / elapsedSeconds;
    double throughputGbps = (dataSizeBytes * 8.0) / (elapsedSeconds * 1e9);

    cout << "Throughput: " << throughputMBps << " MB/s" << endl;
    cout << "Throughput: " << throughputGbps << " Gbps" << endl;


    return 0;
}