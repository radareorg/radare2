/* radare - LGPL - Copyright 2017 - wargio */

#ifndef LIBPS_INTERNAL_H
#define LIBPS_INTERNAL_H
#include <r_types.h>

#define TYPE_NONE 0
#define TYPE_REG  1
#define TYPE_IMM  2
#define TYPE_MEM  3
#define TYPE_CR   4

#define OP(x) ((((ut32)(x)) & 0x3f) << 26)
#define OP_MASK OP(0x3f)

#define OPS(op, xop) (OP(op) | ((((ut32)(xop)) & 0x1f) << 1))
#define OPSC(op, xop, rc) (OPS((op), (xop)) | ((rc) & 1))
#define OPS_MASK   OPSC(0x3f, 0x1f, 1)
#define OPS_MASK_DOT  OPSC(0x3f, 0x1f, 1)

#define OPM(op, xop)  (OP(op) | ((((ut32)(xop)) & 0x3f) << 1))
#define OPMC(op, xop, rc) (OPM((op), (xop)) | ((rc) & 1))
#define OPM_MASK   OPMC(0x3f, 0x3f, 0)

#define OPL(op, xop) (OP(op) | ((((ut32)(xop)) & 0x3ff) << 1))
#define OPLC(op, xop, rc) (OPL((op), (xop)) | ((rc) & 1))
#define OPL_MASK OPLC(0x3f, 0x3ff, 1)
#define OPL_MASK_DOT OPLC(0x3f, 0x3ff, 1)

typedef enum {
    NO_OPERAND,
    OP_FA,
    OP_FB,
    OP_FC,
    OP_FD,
    OP_FS = OP_FD,
    OP_crfD,
    OP_WB,
    OP_IB,
    OP_WC,
    OP_IC,
    OP_RA,
    OP_RB,
    OP_DRA,
    OP_DRB,
} ps_operand_id_t;

typedef enum {
    psq_lx,
    psq_stx,
    psq_lux,
    psq_stux,
    psq_l,
    psq_lu,
    psq_st,
    psq_stu,

    ps_div,
    ps_div_dot,
    ps_sub,
    ps_sub_dot,
    ps_add,
    ps_add_dot,
    ps_sel,
    ps_sel_dot,
    ps_res,
    ps_res_dot,
    ps_mul,
    ps_mul_dot,
    ps_rsqrte,
    ps_rsqrte_dot,
    ps_msub,
    ps_msub_dot,
    ps_madd,
    ps_madd_dot,
    ps_nmsub,
    ps_nmsub_dot,
    ps_nmadd,
    ps_nmadd_dot,
    ps_neg,
    ps_neg_dot,
    ps_mr,
    ps_mr_dot,
    ps_nabs,
    ps_nabs_dot,
    ps_abs,
    ps_abs_dot,

    ps_sum0,
    ps_sum0_dot,
    ps_sum1,
    ps_sum1_dot,
    ps_muls0,
    ps_muls0_dot,
    ps_muls1,
    ps_muls1_dot,
    ps_madds0,
    ps_madds0_dot,
    ps_madds1,
    ps_madds1_dot,
    ps_cmpu0,
    ps_cmpo0,
    ps_cmpu1,
    ps_cmpo1,
    ps_merge00,
    ps_merge00_dot,
    ps_merge01,
    ps_merge01_dot,
    ps_merge10,
    ps_merge10_dot,
    ps_merge11,
    ps_merge11_dot,
    ps_dcbz_l,
} ps_insn_type_t;

typedef struct {
    ps_insn_type_t insn;
    const char* name;
    unsigned int opcode;
    unsigned int mask;
    unsigned char operands[6];
    const char* description;
} ps_opcode_t;

typedef struct {
    int bits;
    int shift;
} ps_operand_t;

#endif /* LIBPS_INTERNAL_H */

