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


/*
 * Import u_intXX_t size_t type definitions from system headers.  You
 * may need to change this, or define these things yourself in this
 * file.
 */
#include <r_types.h>


/*** SHA-256/384/512 Various Length Definitions ***********************/
#define r_SHA256_BLOCK_LENGTH		64
#define r_SHA256_DIGEST_LENGTH		32
#define r_SHA256_DIGEST_STRING_LENGTH	(r_SHA256_DIGEST_LENGTH * 2 + 1)
#define r_SHA384_BLOCK_LENGTH		128
#define r_SHA384_DIGEST_LENGTH		48
#define r_SHA384_DIGEST_STRING_LENGTH	(r_SHA384_DIGEST_LENGTH * 2 + 1)
#define r_SHA512_BLOCK_LENGTH		128
#define r_SHA512_DIGEST_LENGTH		64
#define r_SHA512_DIGEST_STRING_LENGTH	(r_SHA512_DIGEST_LENGTH * 2 + 1)


/*** SHA-256/384/512 Context Structures *******************************/
/* NOTE: If your architecture does not define either u_intXX_t types or
 * uintXX_t (from inttypes.h), you may need to define things by hand
 * for your system:
 */
#ifndef u_int8_t
#define u_int8_t unsigned char
#define u_int32_t unsigned int
#define u_int64_t unsigned long long
#endif


/*** SHA-256/384/512 Function Prototypes ******************************/

void r_SHA256_Init(R_SHA256_CTX *);
void r_SHA256_Update(R_SHA256_CTX*, const ut8*, size_t);
void r_SHA256_Final(ut8[r_SHA256_DIGEST_LENGTH], R_SHA256_CTX*);
char* r_SHA256_End(R_SHA256_CTX*, char[r_SHA256_DIGEST_STRING_LENGTH]);
char* r_SHA256_Data(const ut8*, size_t, char[r_SHA256_DIGEST_STRING_LENGTH]);

void r_SHA384_Init(R_SHA384_CTX*);
void r_SHA384_Update(R_SHA384_CTX*, const ut8*, size_t);
void r_SHA384_Final(ut8[r_SHA384_DIGEST_LENGTH], R_SHA384_CTX*);
char* r_SHA384_End(R_SHA384_CTX*, char[r_SHA384_DIGEST_STRING_LENGTH]);
char* r_SHA384_Data(const ut8*, size_t, char[r_SHA384_DIGEST_STRING_LENGTH]);

void r_SHA512_Init(R_SHA512_CTX*);
void r_SHA512_Update(R_SHA512_CTX*, const ut8*, size_t);
void r_SHA512_Final(ut8[r_SHA512_DIGEST_LENGTH], R_SHA512_CTX*);
char* r_SHA512_End(R_SHA512_CTX*, char[r_SHA512_DIGEST_STRING_LENGTH]);
char* r_SHA512_Data(const ut8*, size_t, char[r_SHA512_DIGEST_STRING_LENGTH]);

#ifdef	__cplusplus
}
#endif /* __cplusplus */

#endif /* __r_SHA2_H__ */

