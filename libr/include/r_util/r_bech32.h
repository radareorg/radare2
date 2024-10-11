/* Copyright (c) 2017, 2021 Pieter Wuille
 *  Updated by W0nda in 2024
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef R2_BECH32_H
#define R2_BECH32_H

#ifdef __cplusplus
extern "C" {
#endif

#if R2_USE_NEW_ABI

#include <r_util/bech32.h>

typedef enum {
    BECH32_ENCODING_NONE,
    BECH32_ENCODING_BECH32,
    BECH32_ENCODING_BECH32M
} bech32_encoding;

R_API int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc);
R_API bech32_encoding bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input);
#endif

#ifdef __cplusplus
}
#endif

#endif
