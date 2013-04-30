#ifndef DECODE_H
#define DECODE_H

#include <r_types.h>

st8 *decode(ut32 ins_pos, ut32 *next_ins_pos);

#ifndef USE_DECODE

static boolt is_linear_circular(ut32 ins_bits);
static boolt is_hash(st32 hash_code);
static boolt check_arg(ut32 ins_bits, int *err_code);

static ut32 get_ins_bits(ut32 hash_code, ut32 ins_pos, st8 *ins, ut32 ins_len, ut32 magic_value, int *err_code);
static ut32 get_q_bits(ut32 val, st8 *ins, ut32 ins_len, int *err_code);

static st8 *do_decode(ut32 ins_off, ut32 ins_pos, ut32 two_ins, ut32 *next_ins_pos, st32 *ins_hash_code, int *err_code);
static st8 *decode_ins(st32 hash_code, ut32 ins_pos, ut32 ins_off, ut32 *ins_len_dec, ut32 *reg_len_dec, ut32 *ret_ins_bits, ut32 magic_value, ut8 two_ins, int *err_code);

static st8 *decode_regis(st8 *reg_arg, st32 hash_code, ut32 ins_bits, ut32 *ret_ins_bits, int *err_code);

static st8* get_token_decoded(st32 hash_code, st8 *ins_token, ut32 ins_token_len, st8 *reg_arg, ut32 *ret_ins_bits, ut32 *ret_reg_len, ut32 magic_value, ut32 ins_pos, ut32 ins_len, ut8 two_ins, int *err_code);

#endif

#endif
