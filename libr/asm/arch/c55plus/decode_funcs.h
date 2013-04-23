#ifndef DECODE_FUNCS_H
#define DECODE_FUNCS_H

#include <r_types.h>

st8 *get_tc2_tc1(ut32 ins_bits);
st8 *get_trans_reg(ut32 ins_bits);
st8 *get_AR_regs_class1(ut32 ins_bits);
st8 *get_AR_regs_class2(ut32 ins_bits, ut32 *ret_len, ut32 ins_pos, ut32 idx);
st8 *get_reg_pair(ut32 idx);
st8 *get_reg_name_3(ut32 idx);
st8 *get_reg_name_2(ut32 idx);
st8 *get_reg_name_1(ut32 idx);
st8 *get_status_regs_and_bits(st8 *reg_arg, ut32 reg_bit);
st8 *get_reg_name_4(ut32 idx);
st8 *get_opers(ut8 oper_byte);
st8 *get_cmp_op(ut32 idx);
st8 *get_sim_reg(st8 *reg_arg, ut32 ins_bits);

#endif
