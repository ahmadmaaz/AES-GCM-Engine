//
// Created by ahmad on 12/4/2024.
//

#include <bitset>
#include "Ghash.h"
#include "Utils.h"
#include <immintrin.h>

namespace Ghash{
    void clmul_x86(uint8_t r[16], const uint8_t a[16], const uint8_t b[16])
    {
        const __m128i MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

        __m128i a1 = _mm_loadu_si128((const __m128i*)a);
        __m128i b1 = _mm_loadu_si128((const __m128i*)b);

        a1 = _mm_shuffle_epi8(a1, MASK);
        b1 = _mm_shuffle_epi8(b1, MASK);

        __m128i T0, T1, T2, T3, T4, T5;

        T0 = _mm_clmulepi64_si128(a1, b1, 0x00);
        T1 = _mm_clmulepi64_si128(a1, b1, 0x01);
        T2 = _mm_clmulepi64_si128(a1, b1, 0x10);
        T3 = _mm_clmulepi64_si128(a1, b1, 0x11);

        T1 = _mm_xor_si128(T1, T2);
        T2 = _mm_slli_si128(T1, 8);
        T1 = _mm_srli_si128(T1, 8);
        T0 = _mm_xor_si128(T0, T2);
        T3 = _mm_xor_si128(T3, T1);

        T4 = _mm_srli_epi32(T0, 31);
        T0 = _mm_slli_epi32(T0, 1);

        T5 = _mm_srli_epi32(T3, 31);
        T3 = _mm_slli_epi32(T3, 1);

        T2 = _mm_srli_si128(T4, 12);
        T5 = _mm_slli_si128(T5, 4);
        T4 = _mm_slli_si128(T4, 4);
        T0 = _mm_or_si128(T0, T4);
        T3 = _mm_or_si128(T3, T5);
        T3 = _mm_or_si128(T3, T2);

        T4 = _mm_slli_epi32(T0, 31);
        T5 = _mm_slli_epi32(T0, 30);
        T2 = _mm_slli_epi32(T0, 25);

        T4 = _mm_xor_si128(T4, T5);
        T4 = _mm_xor_si128(T4, T2);
        T5 = _mm_srli_si128(T4, 4);
        T3 = _mm_xor_si128(T3, T5);
        T4 = _mm_slli_si128(T4, 12);
        T0 = _mm_xor_si128(T0, T4);
        T3 = _mm_xor_si128(T3, T0);

        T4 = _mm_srli_epi32(T0, 1);
        T1 = _mm_srli_epi32(T0, 2);
        T2 = _mm_srli_epi32(T0, 7);
        T3 = _mm_xor_si128(T3, T1);
        T3 = _mm_xor_si128(T3, T2);
        T3 = _mm_xor_si128(T3, T4);

        T3 = _mm_shuffle_epi8(T3, MASK);

        _mm_storeu_si128((__m128i*)r, T3);
    }
}