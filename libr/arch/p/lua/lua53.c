/* radare2 - LGPL - Copyright 2017-2022 - pancake */

#include <r_asm.h>
#include <stdio.h>
#include "lua53.h"

typedef struct plugin_data_t {
	ut32 instructions[256];
	ut32 current_write_index;
} PluginData;

#define isAlpha(x) (('a' <= (x) && 'z' >= (x)) || ('A' <= (x) && 'Z' >= (x)))
#define isNumeric(x) ('0' <= (x) && '9' >= (x))
#define isWhitespace(x) (' ' == (x) || '\t' == (x))
#define isComment(x) (';' == (x))

#define doParse0(state, inc, func, str) {						\
		int temp = func (state, str + inc);					\
		if (temp < 0) {							\
			R_LOG_DEBUG ("%i from %s in String %s", temp,#func, str + inc);\
			return -1;						\
		}								\
		inc += temp;							\
}
#define doParse1(state, inc, func, str, ...) {						\
		int temp = func (state, str + inc, __VA_ARGS__);			\
		if (temp < 0) {							\
			R_LOG_DEBUG ("%i from %s in String %s", temp,#func, str + inc);\
			return -1;						\
		}								\
		inc += temp;							\
}

typedef enum {
	PARAMETER_A,
	PARAMETER_B,
	PARAMETER_C,
	PARAMETER_Ax,
	PARAMETER_Bx,
	PARAMETER_sBx
} Parameter;

static int parseParameters(PluginData *state, const char *str, OpCode opCode);
static int parseParameter(PluginData *state, const char *str, Parameter parameter);
static int parseNextInstruction(PluginData *state, const char *str);
static int parseWhitespaces(PluginData *state, const char *str);

const char *instruction_names[] = {
	"move", "loadk", "loadkx", "loadbool", "loadnil", "getupval", "gettabup", "gettable", "settabup", "setupval", "settable", "newtable", "self", "add", "sub", "mul", "mod",
	"pow", "div", "idiv", "band", "bor", "bxor", "shl", "shr", "unm", "bnot", "not", "len", "concat", "jmp", "eq", "lt", "le",
	"test", "testset", "call", "tailcall", "return", "forloop", "forprep", "tforcall", "tforloop", "setlist", "closure", "vararg", "extraarg", 0
};

static ut32 getInstruction(const ut8 *data){
	ut32 instruction = 0;
	instruction |= data[3] << 24;
	instruction |= data[2] << 16;
	instruction |= data[1] << 8;
	instruction |= data[0] << 0;
	return instruction;
}

static void setInstruction(ut32 opcode, ut8 *data) {
	data[3] = opcode >> 24;
	data[2] = opcode >> 16;
	data[1] = opcode >> 8;
	data[0] = opcode >> 0;
}

static int findNextWordStart(PluginData *state, const char *str){
	int chars_skipped = 0;
	char c;
	char comment_char;
	while (1) {
		doParse0 (state, chars_skipped, parseWhitespaces, str);
		c = str[chars_skipped];
		if (isAlpha (c) || isNumeric (c) || c == '-') {	// if alphanumeric character return position
			return chars_skipped;
		} else if (c == ';') {	// skip comment
			do {
				++chars_skipped;
				comment_char = str[chars_skipped];
			} while (comment_char != '\n');	// if no newline
		} else if (c == '\n') {	// skip comment
			++chars_skipped;
			continue;
		} else if (c == '\0') {
			break;
		} else {
			R_LOG_DEBUG ("Invalic Char 0x%02x", c);
			return -1;
		}
	}
	R_LOG_DEBUG ("Parsed %i empty chars", chars_skipped);
	return chars_skipped;
}

static int parseNextInstruction(PluginData *state, const char *str) {
	int chars_skipped = 0;
	doParse0 (state, chars_skipped, findNextWordStart, str);
	const char *str_ptr = str + chars_skipped;

	int i;
	for (i = 0; instruction_names[i] != 0; i++) {	// iterate over instruction strings
		bool accepted = true;
		int j;
		for (j = 0; instruction_names[i][j] != '\0'; j++) {	// iterate over characters
			if (!((instruction_names[i][j] == str_ptr[j]) || (instruction_names[i][j] == (str_ptr[j] - 'A' + 'a')))) {	// if char or uppercase char does not match
				accepted = false;
				break;
			}
		}
		if (((isWhitespace (str_ptr[j]) || isComment (str_ptr[j])) && accepted)) {	// if this is longest match possible
			// write operation
			chars_skipped += j;
			R_LOG_DEBUG ("Opcode %i Instruction %s", i, instruction_names[i]);

			SET_OPCODE (state->instructions[state->current_write_index], i);	// sets the opcode

			doParse1 (state, chars_skipped, parseParameters, str, i);	// Parse parameters

			state->current_write_index++;	// finished parsing an instruction so increase index
			return chars_skipped;
		}
	}
	R_LOG_DEBUG ("Error");
	return -1;
}

static int parseWhitespaces(PluginData *state, const char *str){
	int skipped_whitespace = 0;
	char c = str[skipped_whitespace];
	while (isWhitespace (c)) {
		c = str[++skipped_whitespace];
	}
	R_LOG_DEBUG ("Parsed %i Whitespaces", skipped_whitespace);
	return skipped_whitespace;
}

static int parseParameters(PluginData *state, const char *str, OpCode opCode) {
	int chars_skipped = 0;
	doParse0 (state, chars_skipped, parseWhitespaces, str);
	switch (opCode) {
	case OP_LOADKX:		/*  A       R(A) := Kst(extra arg)                          */
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_A);
		break;
	case OP_MOVE:		/*  A B     R(A) := R(B)                                    */
	case OP_LOADNIL:	/*  A B     R(A), R(A+1), ..., R(A+B) := nil                */
	case OP_GETUPVAL:	/*  A B     R(A) := UpValue[B]                              */
	case OP_SETUPVAL:	/*  A B     UpValue[B] := R(A)                              */
	case OP_UNM:		/*  A B     R(A) := -R(B)                                   */
	case OP_BNOT:		/*  A B     R(A) := ~R(B)                                   */
	case OP_NOT:		/*  A B     R(A) := not R(B)                                */
	case OP_LEN:		/*  A B     R(A) := length of R(B)                          */
	case OP_RETURN:		/*  A B     return R(A), ... ,R(A+B-2)      (see note)      */
	case OP_VARARG:		/*  A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_A);
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_B);
		break;
	case OP_TEST:		/*  A C     if not (R(A) <=> C) then pc++                   */
	case OP_TFORCALL:	/*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_A);
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_C);
		break;
	case OP_LOADK:		/*  A Bx    R(A) := Kst(Bx)                                 */
	case OP_CLOSURE:	/*  A Bx    R(A) := closure(KPROTO[Bx])                     */
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_A);
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_Bx);
		break;
	case OP_LOADBOOL:	/*  A B C   R(A) := (Bool)B; if (C) pc++                    */
	case OP_GETTABUP:	/*  A B C   R(A) := UpValue[B][RK(C)]                       */
	case OP_GETTABLE:	/*  A B C   R(A) := R(B)[RK(C)]                             */
	case OP_SETTABUP:	/*  A B C   UpValue[A][RK(B)] := RK(C)                      */
	case OP_SETTABLE:	/*  A B C   R(A)[RK(B)] := RK(C)                            */
	case OP_NEWTABLE:	/*  A B C   R(A) := {} (size = B,C)                         */
	case OP_SELF:		/*  A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
	case OP_ADD:		/*  A B C   R(A) := RK(B) + RK(C)                           */
	case OP_SUB:		/*  A B C   R(A) := RK(B) - RK(C)                           */
	case OP_MUL:		/*  A B C   R(A) := RK(B) * RK(C)                           */
	case OP_MOD:		/*  A B C   R(A) := RK(B) % RK(C)                           */
	case OP_POW:		/*  A B C   R(A) := RK(B) ^ RK(C)                           */
	case OP_DIV:		/*  A B C   R(A) := RK(B) / RK(C)                           */
	case OP_IDIV:		/*  A B C   R(A) := RK(B) // RK(C)                          */
	case OP_BAND:		/*  A B C   R(A) := RK(B) & RK(C)                           */
	case OP_BOR:		/*  A B C   R(A) := RK(B) | RK(C)                           */
	case OP_BXOR:		/*  A B C   R(A) := RK(B) ~ RK(C)                           */
	case OP_SHL:		/*  A B C   R(A) := RK(B) << RK(C)                          */
	case OP_SHR:		/*  A B C   R(A) := RK(B) >> RK(C)                          */
	case OP_CONCAT:		/*  A B C   R(A) := R(B).. ... ..R(C)                       */
	case OP_EQ:		/*  A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	case OP_LT:		/*  A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	case OP_LE:		/*  A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
	case OP_TESTSET:	/*  A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
	case OP_CALL:		/*  A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
	case OP_TAILCALL:	/*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
	case OP_SETLIST:	/*  A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_A);
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_B);
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_C);
		break;
	case OP_JMP:		/*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
	case OP_FORLOOP:	/*   A sBx   R(A)+=R(A+2);
				                                if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
	case OP_FORPREP:	/*   A sBx   R(A)-=R(A+2); pc+=sBx                           */
	case OP_TFORLOOP:	/*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_A);
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_sBx);
		break;
	case OP_EXTRAARG:	/*   Ax      extra (larger) argument for previous opcode     */
		doParse1 (state, chars_skipped, parseParameter, str, PARAMETER_Ax);
		break;
	}
	return chars_skipped;
}

static int parseParameter(PluginData *state, const char *str, Parameter parameter) {
	int skipped_chars = findNextWordStart (state, str);
	int resultingNumber = 0;
	bool negative = false;
	if (str[skipped_chars] == '-') {
		negative = true;
		++skipped_chars;
	}
	char c = str[skipped_chars];
	if (!isNumeric (c)) {
		return -1;
	}
	while (isNumeric (c)) {
		resultingNumber *= 10;
		resultingNumber += c - '0';
		c = str[++skipped_chars];
	}
	resultingNumber = negative? resultingNumber * (-1): resultingNumber;
	R_LOG_DEBUG ("Parsed Parameter %i", resultingNumber);
	if (parameter != PARAMETER_sBx && resultingNumber < 0) {
		return -1;
	}
	switch (parameter) {
	case PARAMETER_A:
		SETARG_A (state->instructions[state->current_write_index], resultingNumber);
		break;
	case PARAMETER_B:
		SETARG_B (state->instructions[state->current_write_index], resultingNumber);
		break;
	case PARAMETER_C:
		SETARG_C (state->instructions[state->current_write_index], resultingNumber);
		break;
	case PARAMETER_Ax:
		SETARG_Ax (state->instructions[state->current_write_index], resultingNumber);
		break;
	case PARAMETER_Bx:
		SETARG_Bx (state->instructions[state->current_write_index], resultingNumber);
		break;
	case PARAMETER_sBx:
		SETARG_sBx (state->instructions[state->current_write_index], resultingNumber);
		break;
	}
	return skipped_chars;
}

#if 0
// XXX
int lua53asm(RAsmOp *op, const char *s) {
	int parsed = 0;
	eprintf ("%s\n", s);
	ut32 instruction;
	current_write_prt = &instruction;
	current_write_index = 0;
	doParse0 (parsed, parseNextInstruction, s);

	setInstruction (instruction, op->buf);

	eprintf ("%d\n", parsed);
	eprintf ("%08x\n", instruction);
	return 4;
}
#endif

int lua53dissasm(PluginData *state, RAnalOp *op, const ut8 *buf, int len) {
	if (len < 4) {
		op->mnemonic = strdup ("truncated");
		op->type = R_ANAL_OP_TYPE_ILL;
		return 0;
	}
	ut32 instruction = getInstruction (buf);
	OpCode operator = GET_OPCODE (instruction);

	op->mnemonic = strdup ("invalid");
	op->size = 4;
	switch (operator) {
	case OP_LOADKX:		/*  A       R(A) := Kst(extra arg)                          */
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s %i", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction));
		break;
	case OP_MOVE:		/*  A B     R(A) := R(B)                                    */
	case OP_LOADNIL:	/*  A B     R(A), R(A+1), ..., R(A+B) := nil                */
	case OP_GETUPVAL:	/*  A B     R(A) := UpValue[B]                              */
	case OP_SETUPVAL:	/*  A B     UpValue[B] := R(A)                              */
	case OP_UNM:		/*  A B     R(A) := -R(B)                                   */
	case OP_BNOT:		/*  A B     R(A) := ~R(B)                                   */
	case OP_NOT:		/*  A B     R(A) := not R(B)                                */
	case OP_LEN:		/*  A B     R(A) := length of R(B)                          */
	case OP_RETURN:		/*  A B     return R(A), ... ,R(A+B-2)      (see note)      */
	case OP_VARARG:		/*  A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s %i %i", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_B (instruction));
		break;
	case OP_TEST:		/*  A C     if not (R(A) <=> C) then pc++                   */
	case OP_TFORCALL:	/*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s %i %i", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_C (instruction));
		break;
	case OP_LOADK:		/*  A Bx    R(A) := Kst(Bx)                                 */
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s %i Kst(%i)", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_Bx (instruction));
		break;
	case OP_CLOSURE:	/*  A Bx    R(A) := closure(KPROTO[Bx])                     */
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s %i KPROTO(%i)", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_Bx (instruction));
		break;
	case OP_LOADBOOL:	/*  A B C   R(A) := (Bool)B; if (C) pc++                    */
	case OP_NEWTABLE:	/*  A B C   R(A) := {} (size = B,C)                         */
	case OP_CONCAT:		/*  A B C   R(A) := R(B).. ... ..R(C)                       */
	case OP_TESTSET:	/*  A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
	case OP_CALL:		/*  A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
	case OP_TAILCALL:	/*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
	case OP_SETLIST:	/*  A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */
		op->mnemonic = r_str_newf ("%s %i %i %i", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_B (instruction), GETARG_C (instruction));
		break;
	case OP_SELF:		/*  A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]   */
	case OP_GETTABUP:	/*  A B C   R(A) := UpValue[B][RK(C)]             */
	case OP_GETTABLE:	/*  A B C   R(A) := R(B)[RK(C)]                   */
		if (GETARG_C (instruction) & 0x100) {
			op->mnemonic = r_str_newf ("%s %i %i K(%i)", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_B (instruction), GETARG_C (instruction) & 0xFF);
		} else {
			op->mnemonic = r_str_newf ("%s %i %i %i", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_B (instruction), GETARG_C (instruction));
		}
		break;
	case OP_SETTABUP:	/*  A B C   UpValue[A][RK(B)] := RK(C)            */
	case OP_SETTABLE:	/*  A B C   R(A)[RK(B)] := RK(C)                  */
	case OP_ADD:		/*  A B C   R(A) := RK(B) + RK(C)                 */
	case OP_SUB:		/*  A B C   R(A) := RK(B) - RK(C)                 */
	case OP_MUL:		/*  A B C   R(A) := RK(B) * RK(C)                 */
	case OP_MOD:		/*  A B C   R(A) := RK(B) % RK(C)                 */
	case OP_POW:		/*  A B C   R(A) := RK(B) ^ RK(C)                 */
	case OP_DIV:		/*  A B C   R(A) := RK(B) / RK(C)                 */
	case OP_IDIV:		/*  A B C   R(A) := RK(B) // RK(C)                */
	case OP_BAND:		/*  A B C   R(A) := RK(B) & RK(C)                 */
	case OP_BOR:		/*  A B C   R(A) := RK(B) | RK(C)                 */
	case OP_BXOR:		/*  A B C   R(A) := RK(B) ~ RK(C)                 */
	case OP_SHL:		/*  A B C   R(A) := RK(B) << RK(C)                */
	case OP_SHR:		/*  A B C   R(A) := RK(B) >> RK(C)                */
	case OP_EQ:		/*  A B C   if ((RK(B) == RK(C)) ~= A) then pc++  */
	case OP_LT:		/*  A B C   if ((RK(B) <  RK(C)) ~= A) then pc++  */
	case OP_LE:		/*  A B C   if ((RK(B) <= RK(C)) ~= A) then pc++  */

		free (op->mnemonic);
		if (GETARG_B (instruction) & 0x100) {
			if (GETARG_C (instruction) & 0x100) {
				op->mnemonic = r_str_newf ("%s %i K(%i) K(%i)", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_B (instruction) & 0xFF, GETARG_C (instruction) & 0xFF);
			} else {
				op->mnemonic = r_str_newf ("%s %i K(%i) %i", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_B (instruction) & 0xFF, GETARG_C (instruction));
			}
		} else {
			if (GETARG_C (instruction) & 0x100) {
				op->mnemonic = r_str_newf ("%s %i %i K(%i)", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_B (instruction), GETARG_C (instruction) & 0xFF);
			} else {
				op->mnemonic = r_str_newf ("%s %i %i %i", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_B (instruction), GETARG_C (instruction));
			}
		}
		break;
	case OP_JMP:		/*  A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
	case OP_FORLOOP:	/*  A sBx   R(A)+=R(A+2);
				                                if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
	case OP_FORPREP:	/*  A sBx   R(A)-=R(A+2); pc+=sBx                           */
	case OP_TFORLOOP:	/*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s %i %i", instruction_names[GET_OPCODE (instruction)], GETARG_A (instruction), GETARG_sBx (instruction));
		break;
	case OP_EXTRAARG:	/*   Ax      extra (larger) argument for previous opcode     */
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s Kst(%i)", instruction_names[GET_OPCODE (instruction)], GETARG_Ax (instruction));
		break;
	default:
		// invalid
		op->size = -1;
		break;
	}
	return true;
}


#ifdef MAIN_ASM
int main(int argc, char **argv) {

	char *c = "move 1 2\n forprep 13 -2";
	int p = 0;
	PluginData state = {0};
	eprintf ("Parsing String: %s\n", c);
	eprintf ("-----------------------\n");
	doParse0 (state, p, parseNextInstruction, c, (int) strlen (c));
	eprintf ("Parsed Characters %i\n", p);
	eprintf ("%d   %08x\n", state.current_write_index, state.instructions[state.current_write_index - 1]);

	eprintf ("------------\n");

	doParse0 (state, p, parseNextInstruction, c, (int) strlen (c));
	eprintf ("Parsed Characters %i\n", p);
	eprintf ("%d   %08x\n", state.current_write_index, state.instructions[state.current_write_index - 1]);

	eprintf ("------------\n");

	RAsmOp *asmOp = (RAsmOp *) malloc (sizeof (RAsmOp));
	int advanced = lua53dissasm (&state, asmOp, (const ut8 *) state.instructions, 4);

	eprintf ("%s\n", asmOp->buf_asm);
	lua53dissasm (&state, asmOp, (const ut8 *) state.instructions + advanced, 4);
	eprintf ("%s\n", asmOp->buf_asm);

	return 0;
}
#endif	// MAIN_ASM
