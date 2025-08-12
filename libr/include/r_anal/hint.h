#ifndef R2_ANAL_HINT_H
#define R2_ANAL_HINT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum r_anal_addr_hint_type_t {
	R_ANAL_ADDR_HINT_TYPE_IMMBASE, // XXX 0 should be nothing
	R_ANAL_ADDR_HINT_TYPE_JUMP,
	R_ANAL_ADDR_HINT_TYPE_FAIL,
	R_ANAL_ADDR_HINT_TYPE_STACKFRAME,
	R_ANAL_ADDR_HINT_TYPE_PTR,
	R_ANAL_ADDR_HINT_TYPE_NWORD,
	R_ANAL_ADDR_HINT_TYPE_RET,
	R_ANAL_ADDR_HINT_TYPE_NEW_BITS,
	R_ANAL_ADDR_HINT_TYPE_SIZE,
	R_ANAL_ADDR_HINT_TYPE_SYNTAX,
	R_ANAL_ADDR_HINT_TYPE_OPTYPE,
	R_ANAL_ADDR_HINT_TYPE_OPCODE,
	R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET,
	R_ANAL_ADDR_HINT_TYPE_ESIL,
	R_ANAL_ADDR_HINT_TYPE_HIGH,
	R_ANAL_ADDR_HINT_TYPE_VAL
} RAnalAddrHintType;

typedef struct r_anal_addr_hint_record_t {
	RAnalAddrHintType type;
	union {
		char *type_offset;
		int nword;
		ut64 jump;
		ut64 fail;
		int newbits;
		int immbase;
		ut64 ptr;
		ut64 retval;
		char *syntax;
		char *opcode;
		char *esil;
		int optype;
		ut64 size;
		ut64 stackframe;
		ut64 val;
	};
} RAnalAddrHintRecord;

typedef struct r_anal_hint_t {
	ut64 addr;
	ut64 ptr;
	ut64 val; // used to hint jmp rax
	ut64 jump;
	ut64 fail;
	ut64 ret; // hint for function ret values
	char *arch;
	char *opcode;
	char *syntax;
	char *esil;
	char *offset;
	ut32 type;
	ut64 size;
	int bits;
	int new_bits; // change asm.bits after evaluating this instruction
	int immbase;
	bool high; // highlight hint
	int nword;
	ut64 stackframe;
} RAnalHint;

#ifdef __cplusplus
}
#endif

#endif

