#ifndef DECODE_FUNCS_H
#define DECODE_FUNCS_H

#include <r_types.h>

char *get_tc2_tc1(ut32 ins_bits);
char *get_trans_reg(ut32 ins_bits);
char *get_AR_regs_class1(ut32 ins_bits);
char *get_AR_regs_class2(ut32 ins_bits, ut32 *ret_len, ut32 ins_pos, ut32 idx);
char *get_reg_pair(ut32 idx);
char *get_reg_name_3(ut32 idx);
char *get_reg_name_2(ut32 idx);
char *get_reg_name_1(ut32 idx);
char *get_status_regs_and_bits(char *reg_arg, ut32 reg_bit);
char *get_reg_name_4(ut32 idx);
char *get_opers(ut8 oper_byte);
char *get_cmp_op(ut32 idx);
char *get_sim_reg(char *reg_arg, ut32 ins_bits);

#endif
