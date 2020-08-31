/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_lib.h>

#ifndef OR1K_DISAS_H
#define OR1K_DISAS_H

/** Default mask for opcode */
#define INSN_OPCODE_MASK (0b111111ULL * 0x4000000)
#define INSN_OPCODE_SHIFT 26

/** Empty mask for unused operands */
#define INSN_EMPTY_SHIFT 0
#define INSN_EMPTY_MASK 0

/** Mask for N operand */
#define INSN_N_MASK 0b11111111111111111111111111

/** Shift for D operand */
#define INSN_D_SHIFT 21
/** Mask for D operand */
#define INSN_D_MASK (0b11111 * 0x200000)

/** Mask for K operand */
#define INSN_K_MASK 0b1111111111111111

/** Shift for B operand */
#define INSN_B_SHIFT 11
/** Mask for B operand */
#define INSN_B_MASK (0b11111 * 0x800)

/** Shift for A operand */
#define INSN_A_SHIFT 16
/** Mask for A operand */
#define INSN_A_MASK (0b11111 * 0x10000)

/** Mask for I operand */
#define INSN_I_MASK 0b1111111111111111

/** Mask for L operand */
#define INSN_L_MASK 0b111111

/** Shift for first K operand */
#define INSN_K1_SHIFT 21
/** Mask for first K operand */
#define INSN_K1_MASK (0b11111 * 0x200000)

/** Mask for second K operand */
#define INSN_K2_MASK 0b11111111111

typedef enum insn_type {
	INSN_END = 0, /**< end of array indicator */
	INSN_INVAL = 0, /**< invalid opcode */
	INSN_X, /**< no operands */
	INSN_N, /**< 26-bit immediate */
	INSN_DN, /**< 5-bit destination register, then 26-bit immediate */
	INSN_K, /**< 16-bit immediate */
	INSN_DK, /**< 5-bit destination register, then 16-bit immediate */
	INSN_D, /**< 5-bit destination register */
	INSN_B, /**< 5-bit source register */
	INSN_AI, /**< 5-bit source register, then 16-bit immediate */
	INSN_DAI, /**< 5-bit destination register, 5-bit source register, then 16-bit
							immediate */
	INSN_DAK, /**< 5-bit destination register, 5-bit source register, then 16-bit
							immediate */
	INSN_DAL, /**< 5-bit destination register, 5-bit source register, then 6-bit
							immediate */
	INSN_KABK, /**< 5-bit MSB of immediate, 5-bit source register, 5-bit source
							 register, then 11-bit rest of immediate */
	INSN_AB, /**< 5-bit source register, then 5-bit source register */
	INSN_DA, /**< 5-bit destination register, then 5-bit source register */
	INSN_DAB, /**< 5-bit destination register, 5-bit source register, then 5-bit
							source register */
	INSN_IABI, /**< 5-bit MSB of immediate, 5-bit source register, 5-bit source
							 register, then 11-bit rest of immediate */
	INSN_SIZE, /**< number of types */
} insn_type_t;

typedef enum {
	INSN_OPER_K1, /**< 5-bit MSBs of immediate */
	INSN_OPER_K2, /**< 11-bit LSBs of immediate */
	INSN_OPER_A, /**< 5-bit source register */
	INSN_OPER_B, /**< 5-bit source register */
	INSN_OPER_N, /**< 26-bit immediate */
	INSN_OPER_K, /**< 16-bit immediate */
	INSN_OPER_D, /**< 5-bit destination register */
	INSN_OPER_I, /**< 16-bit immediate */
	INSN_OPER_L, /**< 6-bit immediate */
	INSN_OPER_SIZE /**< number of operand types */
} insn_oper_t;

typedef struct {
	int oper;
	ut32 mask;
	ut32 shift;
} insn_oper_descr_t;

typedef struct {
	int type;
	char *format;
	insn_oper_descr_t operands[INSN_OPER_SIZE];
} insn_type_descr_t;

typedef struct {
	ut32 opcode;
	char *name;
	int type;
	int opcode_mask;
	int insn_type; /**< One of \link _RAnalOpType \endlink */
} insn_extra_t;

typedef struct {
	ut32 opcode;
	char *name;
	int type;
	int insn_type; /**< One of \link _RAnalOpType \endlink */
	insn_extra_t *extra;
} insn_t;

extern insn_type_descr_t types[];
extern size_t types_count;

extern insn_extra_t extra_0x5[];
extern insn_extra_t extra_0x6[];
extern insn_extra_t extra_0x8[];
extern insn_extra_t extra_0x2e[];
extern insn_extra_t extra_0x2f[];
extern insn_extra_t extra_0x31[];
extern insn_extra_t extra_0x32[];
extern insn_extra_t extra_0x38[];
extern insn_extra_t extra_0x39[];

extern insn_t or1k_insns[];
extern size_t insns_count;

insn_extra_t *find_extra_descriptor(insn_extra_t *extra_descr, ut32 insn);

/**
 * \brief Performs sign extension of number
 *
 * \param number number to extend
 * \param mask mask under which number is placed
 *
 * \return sign-extended number
 *
 * If mask does not begin on the lsb, space on the right will also be filled with ones
 *
 */
ut32 sign_extend(ut32 number, ut32 mask);

static inline ut32 get_operand_mask(insn_type_descr_t *type_descr, insn_oper_t operand) {
	return type_descr->operands[operand].mask;
}

static inline ut32 get_operand_shift(insn_type_descr_t *type_descr, insn_oper_t operand) {
	return type_descr->operands[operand].shift;
}

static inline ut32 get_operand_value(ut32 insn, insn_type_descr_t *type_descr, insn_oper_t operand) {
	return (insn & get_operand_mask(type_descr, operand)) >> get_operand_shift(type_descr, operand);
}

static inline int has_type_descriptor(insn_type_t type) {
	return types + types_count > &types[type];
}

static inline int is_type_descriptor_defined(insn_type_t type) {
	return types[type].type == type;
}

static inline insn_type_t type_of_opcode(insn_t *descr, insn_extra_t *extra_descr) {
	r_return_val_if_fail (descr, INSN_END);

	if (extra_descr == NULL) {
		return descr->type;
	} else {
		return extra_descr->type;
	}
}

#endif /* OR1K_DISAS_H */
