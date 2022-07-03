/* TODO: <LICENSE INFO HERE> */
#ifndef ASM_KVX_H
#define ASM_KVX_H

#include <stdint.h>
#include <r_types.h>

#define KVX_MAX_SYLLABLES 3
#define KVX_MAX_OPERANDS 7
#define KVX_MAX_BUNDLE_ISSUE 6
#define KVX_MAX_BUNDLE_WORDS 8

#define BUNDLE_ISSUE_BCU 0
#define BUNDLE_ISSUE_TCA 1
#define BUNDLE_ISSUE_ALU0 2
#define BUNDLE_ISSUE_ALU1 3
#define BUNDLE_ISSUE_MAU 4
#define BUNDLE_ISSUE_LSU 5

#define STEERING_BCU 0
#define STEERING_LSU 1
#define STEERING_MAU 2
#define STEERING_ALU 3

#define IMMX_ISSUE_ALU0 0
#define IMMX_ISSUE_ALU1 1
#define IMMX_ISSUE_MAU 2
#define IMMX_ISSUE_LSU 3

typedef struct {
	int type;
#define KVX_OPER_TYPE_UNK 0
#define KVX_OPER_TYPE_REG 1
#define KVX_OPER_TYPE_IMM 2
#define KVX_OPER_TYPE_OFF 3
	const char *reg;
	ut64 imm;
} operand_t;

typedef struct {
	const char *mnemonic;
	const char *format;
	int len;
	ut32 mask[KVX_MAX_SYLLABLES];
	ut32 value[KVX_MAX_SYLLABLES];
	void (*decode[4])(operand_t *, const ut32 *);
	ut32 type;
	ut32 cond;
} opc_t;

typedef struct {
	const opc_t *opc;
	int rem;
	int len;
	ut32 value[KVX_MAX_SYLLABLES];
} insn_t;

typedef struct {
	ut64 addr;
	int size;
	insn_t issue[KVX_MAX_BUNDLE_ISSUE];
} bundle_t;

int kvx_instr_print(insn_t *insn, ut64 offset, char *buf, size_t len);
ut64 kvx_instr_jump(insn_t *insn, ut64 offset);
insn_t *kvx_next_insn(bundle_t *bundle, ut64 addr, const ut8 *buf, int len);

#endif
