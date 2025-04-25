//
// Created by ahmad on 12/4/2024.
//

#ifndef AES_PARALELIZED_GHASH_H
#define AES_PARALELIZED_GHASH_H

#include <emmintrin.h>
#include "Utils.h"

namespace Ghash {
    void clmul_x86(uint8_t r[16], const uint8_t a[16], const uint8_t b[16]);

    __m128i gf128Reduce(__m128i hi, __m128i lo);

    void gf128MultiplyRaw(const uint8_t* a, const uint8_t* b, __m128i& lo, __m128i& hi);
}

#endif //AES_PARALELIZED_GHASH_H
