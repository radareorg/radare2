/*
 * FILE:	sha2.h
 * AUTHOR:	Aaron D. Gifford <me@aarongifford.com>
 *
 * Copyright (c) 2000-2001, Aaron D. Gifford
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __SHA2_H__
#define __SHA2_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <r_hash.h>
#include <r_util/r_assert.h>
#include <r_types.h>

#if R_CRYPTO_INTERNAL
#undef R_IPI
#define R_IPI R_UNUSED static
#define IPI static
#define R_SHA2_API(x) __sha2_##x
#else
#define R_SHA2_API(x) x
#endif

/*** SHA-256/384/512 Various Length Definitions ***********************/
#define R_SHA256_BLOCK_LENGTH		64
#define R_SHA256_DIGEST_LENGTH		32
#define R_SHA256_DIGEST_STRING_LENGTH	((R_SHA256_DIGEST_LENGTH * 2) + 1)
#define R_SHA384_BLOCK_LENGTH		128
#define R_SHA384_DIGEST_LENGTH		48
#define R_SHA384_DIGEST_STRING_LENGTH	((R_SHA384_DIGEST_LENGTH * 2) + 1)
#define R_SHA512_BLOCK_LENGTH		128
#define R_SHA512_DIGEST_LENGTH		64
#define R_SHA512_DIGEST_STRING_LENGTH	((R_SHA512_DIGEST_LENGTH * 2) + 1)

/*** SHA-256/384/512 Function Prototypes ******************************/

R_IPI void R_SHA2_API(r_sha256_init)(RSha256Context *);
R_IPI void R_SHA2_API(r_sha256_update)(RSha256Context*, const ut8*, size_t);
R_IPI void R_SHA2_API(r_sha256_final)(ut8[R_SHA256_DIGEST_LENGTH], RSha256Context*);
R_IPI char* R_SHA2_API(r_sha256_end)(RSha256Context*, char[R_SHA256_DIGEST_STRING_LENGTH]);
R_IPI char* R_SHA2_API(r_sha256_data)(const ut8*, size_t, char[R_SHA256_DIGEST_STRING_LENGTH]);

R_IPI void R_SHA2_API(r_sha384_init)(RSha384Context*);
R_IPI void R_SHA2_API(r_sha384_update)(RSha384Context*, const ut8*, size_t);
R_IPI void R_SHA2_API(r_sha384_final)(ut8[R_SHA384_DIGEST_LENGTH], RSha384Context*);
R_IPI char* R_SHA2_API(r_sha384_end)(RSha384Context*, char[R_SHA384_DIGEST_STRING_LENGTH]);
R_IPI char* R_SHA2_API(r_sha384_data)(const ut8*, size_t, char[R_SHA384_DIGEST_STRING_LENGTH]);

R_IPI void R_SHA2_API(r_sha512_init)(RSha512Context*);
R_IPI void R_SHA2_API(r_sha512_update)(RSha512Context*, const ut8*, size_t);
R_IPI void R_SHA2_API(r_sha512_final)(ut8[R_SHA512_DIGEST_LENGTH], RSha512Context*);
R_IPI char* R_SHA2_API(r_sha512_end)(RSha512Context*, char[R_SHA512_DIGEST_STRING_LENGTH]);
R_IPI char* R_SHA2_API(r_sha512_data)(const ut8*, size_t, char[R_SHA512_DIGEST_STRING_LENGTH]);

#ifdef	__cplusplus
}
#endif /* __cplusplus */

#endif /* __r_SHA2_H__ */

