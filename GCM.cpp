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
#include <algorithm>
#include <functional>
using namespace Utils;


class GCM {
private:
    Block key;
    Block IV;
    Block AAD;

    void prepareCounter(Block& counter, const Block& IV) {
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



    void incrementCounter(Block& counter) {
        for (int i = 15; i >= 12; --i) { // Last 4 bytes represent the counter
            if (++counter[i] != 0) {
                break; // Stop incrementing if no overflow
            }
        }
    }

    vector<Block> GCTR(const Block& ICB, const Block& val) {
        vector<Block> X = nest(val, 16);
        vector<Block> res(X.size(),Block(16));

        // Precompute counters
        vector<Block> counters(X.size());
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
                Block encryptedBlock;
                aes.encrypt(counters[i],encryptedBlock);
                xorF(encryptedBlock.data(), X[i].data(), res[i].data());
            }
        }

        return res;
    }
#pragma omp declare reduction(xorReduction : Block : \
    omp_out = xorF(omp_out, omp_in)) initializer(omp_priv = Block(16, 0x00))

    Block GHASH(const Block &val, const Block &H) {
        // Split input into 16-byte blocks
        vector<Block> X = nest(val, 16);
        int numBlocks = X.size();

        vector<Block> gf128Res;

        this->computeGF128Power(H, numBlocks,gf128Res);

        Block tag(16, 0x00);

#pragma omp parallel for reduction(xorReduction : tag)
        for (int i = 0; i < numBlocks; ++i) {
            Block hPower = gf128Res[numBlocks - i - 1];

            Block term = gf128Multiply(X[i], hPower);
//            tag = xorF2(tag,term);

            xorF(tag.data(),term.data(),tag.data());
        }

        return tag;
    }

    Block gf128Multiply(const Block &X, const Block &H) {

        Block result(16);
        Ghash::clmul_x86(result.data(), X.data(), H.data());
        return result;
    }
    void computeGF128Power(const Block&H,int size,vector<Block>& gf128Res){
        gf128Res.resize(size);
        gf128Res[0]=H;
        for(int i =1;i<size;i++){
            gf128Res[i] = gf128Multiply(gf128Res[i-1],H);
        }
    }
    Block padC(const Block& C, int u, int v, uint64_t sizeOfC, uint64_t sizeOfA) {
        size_t totalSize = AAD.size() + (v / 8) + C.size() + (u / 8) + 16;
        Block res;
        res.reserve(totalSize);

        res.insert(res.end(), AAD.begin(), AAD.end());
        res.resize(res.size() + v / 8, 0x00);
        res.insert(res.end(), C.begin(), C.end());
        res.resize(res.size() + u / 8, 0x00);

        Block lenA64 = encodeLength(sizeOfA);
        Block lenC64 = encodeLength(sizeOfC);

        res.insert(res.end(), lenA64.begin(), lenA64.end());
        res.insert(res.end(), lenC64.begin(), lenC64.end());

        return res;
    }


    Block encodeLength(uint64_t len) {
        Block encoded(8, 0);
        for (int i = 7; i >= 0; --i) {
            encoded[i] = len & 0xFF;
            len >>= 8;
        }
        return encoded;
    }


public:


    pair<Block, Block> encrypt(const Block& key,  const Block& IV, const Block& AAD,const Block& P) {
        this->AAD= AAD;
        this->IV = IV;
        this->key = key;

        AES aes(key);
        int sizeOfPlainText = P.size();

        Block H;
        aes.encrypt(Block(16, 0x00),H);

        Block J0;
        prepareCounter(J0, this->IV);
        incrementCounter(J0);

        vector<Block> C = GCTR(J0, P);

        Block newC = flatten(C);

        // Clean C
        C.clear();
        C.shrink_to_fit();

        while (sizeOfPlainText < newC.size()) {
            newC.pop_back();
            sizeOfPlainText++;
        }

        int sizeOfCinBits = newC.size() * 8;
        int sizeofAADinBits = AAD.size() * 8;

        int u = (128 * ceil((double) sizeOfCinBits / 128)) - sizeOfCinBits;
        int v = (128 * ceil((double) sizeofAADinBits / 128)) - sizeofAADinBits;


        Block S = GHASH(padC(newC, u, v, sizeOfCinBits, sizeofAADinBits), H);


        vector<Block> T = GCTR(J0, S);
        Block newT = flatten(T);


        return { newC, newT };
    }


};

int main(){
    omp_set_num_threads(12);

    // Key (16 bytes)
    Block Key = {};

    for(int i =0;i<32;i++){
        Key.push_back(0x00);
    }
    Block P ;
    long long N = 1000000 *100  ;
    for(int i =0;i<N;i++){
        P.push_back(0x00);
    }

    // IV (Initialization Vector, 12 bytes)
    Block IV = {};
    for(int i =0;i<12;i++){
        IV.push_back(0x00);

    }

    // A (Associated Data, 20 bytes)
    Block A = {

    };


    auto start_time = chrono::high_resolution_clock::now();

    GCM gcm;
    pair<Block, Block> res = gcm.encrypt(Key, IV, A,P);
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