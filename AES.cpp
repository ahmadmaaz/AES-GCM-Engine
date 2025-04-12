#include <wmmintrin.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <vector>

using namespace std;

typedef vector<uint8_t> ByteVector;

class AES {
private:
    ByteVector key;
    __m128i key_schedule[15];

public:
    AES(const ByteVector& givenKey) {
        if (givenKey.size() != 32) {
            throw std::runtime_error("Key must be 256 bits (32 bytes)");
        }
        key = givenKey;
        key_expansion(key, key_schedule);
    }

    static __m128i key_expansion_part_1(__m128i key, __m128i keygened) {
        keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        return _mm_xor_si128(key, keygened);
    }

    static __m128i key_expansion_part_2(__m128i key_lower, __m128i key_upper) {
        key_upper = _mm_xor_si128(key_upper, _mm_slli_si128(key_upper, 0x4));
        key_upper = _mm_xor_si128(key_upper, _mm_slli_si128(key_upper, 0x4));
        key_upper = _mm_xor_si128(key_upper, _mm_slli_si128(key_upper, 0x4));
        return _mm_xor_si128(key_upper, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(key_lower, 0x00), 0xaa));
    }

    void key_expansion(const ByteVector& userkey, __m128i* Key_Schedule) {
        __m128i lh = _mm_loadu_si128((__m128i*)userkey.data());
        __m128i uh = _mm_loadu_si128((__m128i*)(userkey.data() + 16));

        Key_Schedule[0] = lh;
        Key_Schedule[1] = uh;

        Key_Schedule[2] = key_expansion_part_1(Key_Schedule[0], _mm_aeskeygenassist_si128(Key_Schedule[1], 0x01));
        Key_Schedule[3] = key_expansion_part_2(Key_Schedule[2], Key_Schedule[1]);

        Key_Schedule[4] = key_expansion_part_1(Key_Schedule[2], _mm_aeskeygenassist_si128(Key_Schedule[3], 0x02));
        Key_Schedule[5] = key_expansion_part_2(Key_Schedule[4], Key_Schedule[3]);

        Key_Schedule[6] = key_expansion_part_1(Key_Schedule[4], _mm_aeskeygenassist_si128(Key_Schedule[5], 0x04));
        Key_Schedule[7] = key_expansion_part_2(Key_Schedule[6], Key_Schedule[5]);

        Key_Schedule[8] = key_expansion_part_1(Key_Schedule[6], _mm_aeskeygenassist_si128(Key_Schedule[7], 0x08));
        Key_Schedule[9] = key_expansion_part_2(Key_Schedule[8], Key_Schedule[7]);

        Key_Schedule[10] = key_expansion_part_1(Key_Schedule[8], _mm_aeskeygenassist_si128(Key_Schedule[9], 0x10));
        Key_Schedule[11] = key_expansion_part_2(Key_Schedule[10], Key_Schedule[9]);

        Key_Schedule[12] = key_expansion_part_1(Key_Schedule[10], _mm_aeskeygenassist_si128(Key_Schedule[11], 0x20));
        Key_Schedule[13] = key_expansion_part_2(Key_Schedule[12], Key_Schedule[11]);

        Key_Schedule[14] = key_expansion_part_1(Key_Schedule[12], _mm_aeskeygenassist_si128(Key_Schedule[13], 0x40));
    }

    void encrypt(const ByteVector& plaintext, ByteVector& ciphertext) {
        ciphertext.resize(16);

        __m128i plaintext_block = _mm_loadu_si128((__m128i*)plaintext.data());
        plaintext_block = _mm_xor_si128(plaintext_block, key_schedule[0]);

        for (int i = 1; i < 14; i++) {
            plaintext_block = _mm_aesenc_si128(plaintext_block, key_schedule[i]);
        }
        plaintext_block = _mm_aesenclast_si128(plaintext_block, key_schedule[14]);

        _mm_storeu_si128((__m128i*)ciphertext.data(), plaintext_block);
    }

    void decrypt(const ByteVector& ciphertext, ByteVector& plaintext) {
        plaintext.resize(16);

        __m128i ciphertext_block = _mm_loadu_si128((__m128i*)ciphertext.data());
        ciphertext_block = _mm_xor_si128(ciphertext_block, key_schedule[14]);

        for (int i = 13; i > 0; i--) {
            ciphertext_block = _mm_aesdec_si128(ciphertext_block, _mm_aesimc_si128(key_schedule[i]));
        }

        ciphertext_block = _mm_aesdeclast_si128(ciphertext_block, key_schedule[0]);

        _mm_storeu_si128((__m128i*)plaintext.data(), ciphertext_block);
    }
};