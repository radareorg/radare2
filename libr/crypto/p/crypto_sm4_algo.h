/* radare - LGPL - Copyright 2017-2022 - Sylvain Pelissier
 * Implementation of SM4 block cipher
 * https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10
 *
 * */

#ifndef CRYPTO_SM4_ALGO_H
#define CRYPTO_SM4_ALGO_H

#define BLOCK_SIZE   16
#define SM4_KEY_SIZE 16

#include <r_lib.h>
#include <r_util.h>

/* Round keys */
static R_TH_LOCAL ut32 sm4_sk[32];

/* Family Key FK */
static const ut32 FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

R_API ut32 sm4_RK(ut32 rk);
bool sm4_init(ut32 *sk, const ut8 *key, int keylen, int dir);
void sm4_crypt(const ut32 *sk, const ut8 *inbuf, ut8 *outbuf, int buflen);

#endif // CRYPTO_SM4_ALGO_H