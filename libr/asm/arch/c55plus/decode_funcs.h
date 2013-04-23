#ifdef DECODE_FUNCS_H
#define DECODE_FUNCS_H

char *get_tc2_or_tc1(unsigned int ins_bits);
char *get_trans_reg(unsigned int ins_bits);
char *get_AR_regs_class1(unsigned int ins_bits);
char *get_AR_regs_class2(unsigned int ins_bits, unsigned int *ret_len, unsigned int ins_pos, unsigned int idx);
char *get_reg_pair(unsigned int idx);
char *get_reg_name_3(unsigned int idx);
char *get_reg_name_2(unsigned int idx);
char *get_reg_name_1(unsigned int idx);
char *get_status_regs_and_bits(char *reg_arg, unsigned int reg_bit);
char *get_reg_name_4(unsigned int idx);
char *get_opers(unsigned char oper_byte);
char *get_cmp_op(unsigned int idx);
char *get_sim_reg(char *reg_arg, unsigned int hash_code);

#endif
