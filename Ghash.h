//
// Created by ahmad on 12/4/2024.
//

#ifndef AES_PARALELIZED_GHASH_H
#define AES_PARALELIZED_GHASH_H

#include "Utils.h"

namespace Ghash {

    void clmul_x86(uint8_t r[16], const uint8_t a[16], const uint8_t b[16]);
}

#endif //AES_PARALELIZED_GHASH_H
