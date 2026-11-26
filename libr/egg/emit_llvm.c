/* radare - LGPL - Copyright 2026 - pancake */

#include "egg_private.h"

#define LLVM_MAX_ARGS 32
#define LLVM_RETURN "%ret.slot"

typedef enum {
	LLVM_INVALID,
	LLVM_VOID,
	LLVM_I32,
	LLVM_I64,
	LLVM_PTR,
} LLVMType;

static const char *const llvm_types[] = { "", "void", "i32", "i64", "ptr" };
static const char *const llvm_regs[] = { "%reg.0", "%reg.1", "%reg.2", "%reg.3" };

typedef struct {
	char text[32];
} LLVMValue;

typedef struct {
	char *name;
	RStrBuf body;
	RStrBuf locals;
	LLVMType result;
	LLVMType params[LLVM_MAX_ARGS];
	int arity;
	int used_params;
	int syscall_number;
	bool defined;
	bool external;
	bool exported;
} LLVMFunction;

typedef struct {
	RList *functions;
	Sdb *symbols;
	HtUU *slots;
	RStrBuf strings;
	RStrBuf assembly;
	LLVMFunction *function;
	LLVMValue args[LLVM_MAX_ARGS];
	int temporary;
	int string_id;
	bool terminated;
	bool trap;
	bool uses_syscall;
	bool asm_ready;
	bool failed;
} LLVMState;

static void function_free(void *data) {
	LLVMFunction *function = data;
	free (function->name);
	r_strbuf_fini (&function->body);
	r_strbuf_fini (&function->locals);
	free (function);
}

static void state_free(void *data) {
	LLVMState *state = data;
	r_list_free (state->functions);
	sdb_free (state->symbols);
	ht_uu_free (state->slots);
	r_strbuf_fini (&state->strings);
	r_strbuf_fini (&state->assembly);
	free (state);
}

bool egg_llvm_begin(REgg *egg) {
	if (egg->priv) {
		state_free (egg->priv);
	}
	LLVMState *state = R_NEW0 (LLVMState);
	state->functions = r_list_newf (function_free);
	state->symbols = sdb_new0 ();
	if (!state->functions || !state->symbols || !r_buf_resize (egg->buf, 0)) {
		state_free (state);
		egg->priv = NULL;
		return false;
	}
	egg->priv = state;
	return true;
}

static bool emit_error(REgg *egg, const char *message, const char *detail) {
	LLVMState *state = egg->priv;
	if (!state->failed) {
		R_LOG_ERROR ("%s:%d: LLVM: %s '%s'", r_str_get (egg->lang.file), egg->lang.line, message, r_str_get (detail));
		state->failed = true;
	}
	return false;
}

static LLVMFunction *find_function(REgg *egg, const char *name) {
	LLVMState *state = egg->priv;
	if (R_STR_ISEMPTY (name) || strchr (".0123456789", *name)
			|| name[strspn (name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.")]
			|| r_str_startswith (name, "llvm.")) {
		emit_error (egg, "invalid function name", name);
		return NULL;
	}
	LLVMFunction *function = sdb_ptr_get (state->symbols, name, NULL);
	if (!function) {
		function = R_NEW0 (LLVMFunction);
		function->name = strdup (name);
		function->arity = -1;
		function->syscall_number = -1;
		function->result = !strcmp (name, "main")? LLVM_I32: LLVM_I64;
		if (!function->name || !r_list_append (state->functions, function)) {
			function_free (function);
			emit_error (egg, "cannot add function", name);
			return NULL;
		}
		if (!sdb_ptr_set (state->symbols, name, function, 0)) {
			emit_error (egg, "cannot index function", name);
			return NULL;
		}
	}
	return function;
}

bool egg_llvm_function(REgg *egg, const char *name, bool exported) {
	LLVMState *state = egg->priv;
	LLVMFunction *function = find_function (egg, name);
	if (!function) {
		return false;
	}
	if (state->function || function->defined || function->external || function->syscall_number >= 0) {
		return emit_error (egg, "unexpected function definition", name);
	}
	state->slots = ht_uu_new0 ();
	if (!state->slots) {
		return false;
	}
	function->defined = true;
	function->exported = exported;
	state->function = function;
	state->temporary = 0;
	state->terminated = false;
	memset (egg->lang.nestedi, 0, sizeof (egg->lang.nestedi));
	return true;
}

static LLVMType parse_type(char *name) {
	r_str_trim (name);
	int i;
	for (i = LLVM_VOID; i <= LLVM_PTR; i++) {
		if (!strcmp (name, llvm_types[i])) {
			return i;
		}
	}
	return LLVM_INVALID;
}

bool egg_llvm_extern(REgg *egg, const char *name, char *signature) {
	LLVMFunction *function = find_function (egg, name);
	if (!function) {
		return false;
	}
	if (function->defined || function->external || function->arity >= 0 || function->syscall_number >= 0) {
		return emit_error (egg, "extern declaration must precede uses of", name);
	}
	int count = 0;
	char *type = signature;
	for (;;) {
		char *next = strchr (type, ',');
		if (next) {
			*next++ = 0;
		}
		LLVMType parsed = parse_type (type);
		if (!parsed || (count && parsed == LLVM_VOID) || count > LLVM_MAX_ARGS) {
			return emit_error (egg, "invalid extern signature for", name);
		}
		if (count) {
			function->params[count - 1] = parsed;
		} else {
			function->result = parsed;
		}
		count++;
		if (!next) {
			break;
		}
		type = next;
	}
	function->arity = count - 1;
	function->external = true;
	return true;
}

static LLVMType syscall_type(const REgg *egg) {
	switch (egg->os) {
	case R_EGG_OS_LINUX:
		return egg->bits == 32? LLVM_I32: LLVM_I64;
	case R_EGG_OS_DARWIN:
	case R_EGG_OS_MACOS:
	case R_EGG_OS_OSX:
		return LLVM_I32;
	default:
		return LLVM_INVALID;
	}
}

bool egg_llvm_syscall(REgg *egg, const char *name, const char *number) {
	if (!syscall_type (egg) || (egg->bits != 32 && egg->bits != 64)) {
		return emit_error (egg, "syscall requires a 32- or 64-bit Linux or macOS target", name);
	}
	char *end;
	errno = 0;
	long value = strtol (number, &end, 0);
	if (end == number || *r_str_trim_head_ro (end) || errno == ERANGE || value < 0 || value > ST32_MAX) {
		return emit_error (egg, "invalid syscall number", number);
	}
	LLVMFunction *function = find_function (egg, name);
	if (!function) {
		return false;
	}
	if (function->defined || function->external || function->arity >= 0) {
		return emit_error (egg, "syscall declaration conflicts with function", name);
	}
	function->syscall_number = value;
	return true;
}

static void ir(REgg *egg, const char *format, ...) R_PRINTF_CHECK(2, 3);

static void ir(REgg *egg, const char *format, ...) {
	LLVMState *state = egg->priv;
	if (!state->function) {
		emit_error (egg, "instruction outside a function", "");
		return;
	}
	va_list ap;
	va_start (ap, format);
	if (!r_strbuf_vappendf (&state->function->body, format, ap)) {
		emit_error (egg, "cannot append IR to", state->function->name);
	}
	va_end (ap);
}

static LLVMValue temporary(LLVMState *state) {
	LLVMValue value;
	snprintf (value.text, sizeof (value.text), "%%t%d", ++state->temporary);
	return value;
}

static void ensure_block(REgg *egg) {
	LLVMState *state = egg->priv;
	if (state->terminated) {
		ir (egg, "dead.%d:\n", ++state->temporary);
		state->terminated = false;
	}
}

bool egg_llvm_assembly_line(REgg *egg, const char *line) {
	LLVMState *state = egg->priv;
	line = r_str_trim_head_ro (line);
	if (!state->function) {
		return emit_error (egg, "inline assembly outside a function", line);
	}
	if (strchr (line, '`')) {
		return emit_error (egg, "unsupported variable substitution in inline assembly", line);
	}
	return !*line || r_strbuf_appendf (&state->assembly, "%s\n", line);
}

static const char *assembly_clobbers(const char *arch, int bits) {
	if (!strcmp (arch, "x86")) {
		if (bits == 64) {
			return "~{memory},~{flags},~{rax},~{rcx},~{rdx},~{rsi},~{rdi},~{r8},~{r9},~{r10},~{r11}";
		}
		return "~{memory},~{flags},~{eax},~{ebx},~{ecx},~{edx}";
	}
	if (!strcmp (arch, "arm") && bits == 64) {
		return "~{memory},~{cc},~{x0},~{x1},~{x2},~{x3},~{x4},~{x5},~{x6},~{x7},~{x8},"
			"~{x9},~{x10},~{x11},~{x12},~{x13},~{x14},~{x15},~{x16},~{x17}";
	}
	return "~{memory}";
}

bool egg_llvm_flush_assembly(REgg *egg) {
	LLVMState *state = egg->priv;
	if (r_strbuf_is_empty (&state->assembly)) {
		return true;
	}
	RAsm *assembler = egg->rasm;
	if (!state->asm_ready) {
		char *arch = r_egg_option_get (egg, "llvm.asm.arch");
		const char *name = R_STR_ISNOTEMPTY (arch)? arch: R_SYS_ARCH;
		r_asm_set_bits (assembler, egg->bits);
		r_asm_set_big_endian (assembler, egg->endian);
		r_arch_config_set_syntax (assembler->config, R_ARCH_SYNTAX_INTEL);
		state->asm_ready = r_asm_use (assembler, name);
		if (!state->asm_ready) {
			emit_error (egg, "cannot select inline assembler (set llvm.asm.arch)", name);
		}
		free (arch);
		if (!state->asm_ready) {
			return false;
		}
	}
	r_asm_set_pc (assembler, 0);
	RAsmCode *code = r_asm_assemble (assembler, r_strbuf_get (&state->assembly));
	if (!code || code->len <= 0) {
		r_asm_code_free (code);
		return emit_error (egg, "cannot assemble inline code for", assembler->config->arch);
	}
	ensure_block (egg);
	ir (egg, "  call void asm sideeffect \".byte ");
	int i;
	for (i = 0; i < code->len; i++) {
		ir (egg, "%s0x%02x", i? ", ": "", code->bytes[i]);
	}
	ir (egg, "\", \"%s\"()\n", assembly_clobbers (assembler->config->arch, egg->bits));
	r_asm_code_free (code);
	r_strbuf_set (&state->assembly, "");
	return !state->failed;
}

static LLVMValue read_value(REgg *egg, const char *operand) {
	LLVMValue value = { "0" };
	if (R_STR_ISEMPTY (operand)) {
		emit_error (egg, "expected an operand", operand);
		return value;
	}
	if (*operand == '%') {
		value = temporary (egg->priv);
		ir (egg, "  %s = load i64, ptr %s\n", value.text, operand);
		return value;
	}
	char *end;
	errno = 0;
	ut64 number = strtoull (operand, &end, 0);
	if (end == operand || *r_str_trim_head_ro (end) || errno == ERANGE) {
		emit_error (egg, "invalid operand", operand);
		return value;
	}
	snprintf (value.text, sizeof (value.text), "%" PFMT64u, number);
	return value;
}

static LLVMValue cast_value(REgg *egg, LLVMValue value, LLVMType type, bool to_word) {
	if (type == LLVM_I64) {
		return value;
	}
	LLVMValue result = temporary (egg->priv);
	const char *op = type == LLVM_PTR? (to_word? "ptrtoint": "inttoptr"): (to_word? "sext": "trunc");
	ir (egg, "  %s = %s %s %s to %s\n", result.text, op,
		to_word? llvm_types[type]: "i64", value.text, to_word? "i64": llvm_types[type]);
	return result;
}

static void store_value(REgg *egg, const char *destination, LLVMValue value) {
	if (R_STR_ISEMPTY (destination) || *destination != '%') {
		emit_error (egg, "invalid destination", destination);
		return;
	}
	ir (egg, "  store i64 %s, ptr %s\n", value.text, destination);
}

static void emit_get_var(REgg *egg, int type, RStrBuf *out, int idx) {
	LLVMState *state = egg->priv;
	if (!state->function) {
		emit_error (egg, "local variable outside a function", "");
		return;
	}
	r_strbuf_setf (out, "%%%s.%u", type? "fix": "local", (ut32)idx);
	const ut64 key = ((ut64)(ut32)idx << 1) | type;
	if (!ht_uu_find (state->slots, key, NULL)) {
		if (!ht_uu_insert (state->slots, key, 1)
				|| !r_strbuf_appendf (&state->function->locals, "  %s = alloca i64\n", r_strbuf_get (out))) {
			emit_error (egg, "cannot allocate local", r_strbuf_get (out));
		}
	}
}

static void emit_get_arg(REgg *egg, RStrBuf *out, int idx) {
	LLVMState *state = egg->priv;
	LLVMFunction *function = state->function;
	if (!function || idx < 0 || idx >= LLVM_MAX_ARGS) {
		emit_error (egg, "argument index out of range", "");
		return;
	}
	function->used_params = R_MAX (function->used_params, idx + 1);
	r_strbuf_setf (out, "%%arg.%d", idx);
}

static const char *emit_regs(REgg *egg, int idx) {
	if (idx < 0 || idx >= R_ARRAY_SIZE (llvm_regs)) {
		emit_error (egg, "register index out of range", "");
		return "";
	}
	return llvm_regs[idx];
}

static LLVMValue load_indirect(REgg *egg, const char *operand, int size) {
	LLVMValue address = cast_value (egg, read_value (egg, operand), LLVM_PTR, false);
	LLVMValue value = temporary (egg->priv);
	const char *type = size == 'b'? "i8": "i64";
	ir (egg, "  %s = load %s, ptr %s, align 1\n", value.text, type, address.text);
	if (size == 'b') {
		LLVMValue extended = temporary (egg->priv);
		ir (egg, "  %s = zext i8 %s to i64\n", extended.text, value.text);
		return extended;
	}
	return value;
}

static LLVMValue address_of(REgg *egg, const char *operand) {
	if (R_STR_ISEMPTY (operand) || *operand != '%') {
		emit_error (egg, "expected an addressable variable", operand);
		return (LLVMValue){ "0" };
	}
	LLVMValue value = temporary (egg->priv);
	ir (egg, "  %s = ptrtoint ptr %s to i64\n", value.text, operand);
	return value;
}

static LLVMValue read_operand(REgg *egg, const char *operand, int modifier, int size) {
	if (modifier == '*') {
		return load_indirect (egg, operand, size);
	}
	if (modifier == '&') {
		return address_of (egg, operand);
	}
	return read_value (egg, operand);
}

static void emit_load(REgg *egg, const char *operand, int size) {
	ensure_block (egg);
	store_value (egg, llvm_regs[0], load_indirect (egg, operand, size));
}

static void emit_load_ptr(REgg *egg, const char *operand) {
	ensure_block (egg);
	store_value (egg, llvm_regs[0], address_of (egg, operand));
}

static void emit_mathop(REgg *egg, int op, int size, int type, const char *source, const char *destination) {
	ensure_block (egg);
	LLVMValue value = read_operand (egg, source, type, size);
	const char *instruction;
	switch (op) {
	case '+': instruction = "add"; break;
	case '-': instruction = "sub"; break;
	case '*': instruction = "mul"; break;
	case '/': instruction = "sdiv"; break;
	case '&': instruction = "and"; break;
	case '|': instruction = "or"; break;
	case '^': instruction = "xor"; break;
	default:
		store_value (egg, destination, value);
		return;
	}
	LLVMValue lhs = read_value (egg, destination);
	LLVMValue result = temporary (egg->priv);
	ir (egg, "  %s = %s i64 %s, %s\n", result.text, instruction, lhs.text, value.text);
	store_value (egg, destination, result);
}

static void emit_set_string(REgg *egg, const char *destination, const char *string, int length) {
	LLVMState *state = egg->priv;
	if (length < 0) {
		emit_error (egg, "invalid string literal", "");
		return;
	}
	ensure_block (egg);
	int id = state->string_id++;
	RStrBuf *strings = &state->strings;
	bool ok = r_strbuf_appendf (strings, "@.egg.str.%d = private unnamed_addr constant [%d x i8] c\"", id, length + 1);
	int i;
	for (i = 0; ok && i < length; i++) {
		ut8 byte = string[i];
		if (byte >= 32 && byte < 127 && byte != '"' && byte != '\\') {
			ok = r_strbuf_append_n (strings, string + i, 1);
		} else {
			ok = r_strbuf_appendf (strings, "\\%02X", byte);
		}
	}
	if (!ok || !r_strbuf_append (strings, "\\00\"\n")) {
		emit_error (egg, "cannot append string literal", "");
		return;
	}
	char *slot = r_egg_mkvar (egg, NULL, destination, 0);
	LLVMValue value = temporary (state);
	ir (egg, "  %s = ptrtoint ptr @.egg.str.%d to i64\n", value.text, id);
	store_value (egg, slot, value);
	free (slot);
}

static void emit_push_arg(REgg *egg, int modifier, int index, const char *operand) {
	LLVMState *state = egg->priv;
	if (index > LLVM_MAX_ARGS) {
		emit_error (egg, "too many call arguments for", egg->lang.callname);
		return;
	}
	ensure_block (egg);
	state->args[index - 1] = read_operand (egg, operand, modifier, egg->lang.varsize);
}

static void emit_syscall(REgg *egg, int number, int nargs) {
	LLVMState *state = egg->priv;
	LLVMType result_type = syscall_type (egg);
	LLVMType word_type = egg->bits == 32? LLVM_I32: LLVM_I64;
	const char *type = llvm_types[result_type];
	ensure_block (egg);
	int i;
	for (i = 0; i < nargs; i++) {
		state->args[i] = cast_value (egg, state->args[i], word_type, false);
	}
	LLVMValue result = temporary (state);
	ir (egg, "  %s = call %s (%s, ...) @syscall(%s %d", result.text, type, type, type, number);
	for (i = nargs - 1; i >= 0; i--) {
		ir (egg, ", %s %s", llvm_types[word_type], state->args[i].text);
	}
	ir (egg, ")\n");
	store_value (egg, LLVM_RETURN, cast_value (egg, result, result_type, true));
	state->uses_syscall = true;
}

static void emit_call(REgg *egg, const char *name, int indirect) {
	LLVMState *state = egg->priv;
	if (indirect || !state->function) {
		emit_error (egg, "unsupported call to", name);
		return;
	}
	int nargs = egg->lang.nargs;
	if (nargs > LLVM_MAX_ARGS || state->failed) {
		return;
	}
	LLVMFunction *target = find_function (egg, name);
	if (!target) {
		return;
	}
	if (target->syscall_number >= 0) {
		emit_syscall (egg, target->syscall_number, nargs);
		return;
	}
	if (target->arity >= 0 && target->arity != nargs) {
		emit_error (egg, "inconsistent argument count for", name);
		return;
	}
	target->arity = nargs;
	ensure_block (egg);
	int i;
	for (i = 0; i < nargs; i++) {
		LLVMType type = target->external? target->params[i]: LLVM_I64;
		state->args[nargs - 1 - i] = cast_value (egg, state->args[nargs - 1 - i], type, false);
	}
	LLVMValue result = { "0" };
	if (target->result != LLVM_VOID) {
		result = temporary (state);
		ir (egg, "  %s = call ", result.text);
	} else {
		ir (egg, "  call ");
	}
	ir (egg, "%s @%s(", llvm_types[target->result], name);
	for (i = 0; i < nargs; i++) {
		LLVMType type = target->external? target->params[i]: LLVM_I64;
		ir (egg, "%s%s %s", i? ", ": "", llvm_types[type], state->args[nargs - 1 - i].text);
	}
	ir (egg, ")\n");
	if (target->result != LLVM_VOID) {
		result = cast_value (egg, result, target->result, true);
	}
	store_value (egg, LLVM_RETURN, result);
}

static void emit_get_result(REgg *egg, const char *destination) {
	store_value (egg, destination, read_value (egg, LLVM_RETURN));
}

static void emit_jump(REgg *egg, const char *label, int indirect) {
	LLVMState *state = egg->priv;
	label = r_str_trim_head_ro (label);
	if (indirect || !r_str_startswith (label, "__")) {
		emit_error (egg, "unsupported jump to", label);
		return;
	}
	if (!state->terminated) {
		ir (egg, "  br label %%%s\n", label);
		state->terminated = true;
	}
}

static void emit_label(REgg *egg, const char *name) {
	LLVMState *state = egg->priv;
	emit_jump (egg, name, 0);
	ir (egg, "%s:\n", name);
	state->terminated = false;
}

static void emit_branch(REgg *egg, char *less, char *greater, char *equal, char *negate, int size, const char *dst) {
	LLVMState *state = egg->priv;
	char *lhs = egg->lang.conditionstr;
	char *cmp = less? less: greater? greater: negate && equal? negate: equal;
	const char *predicate = "ne";
	const char *rhs = "0";
	if (cmp) {
		bool inclusive = cmp[1] == '=';
		rhs = cmp + (inclusive? 2: 1);
		predicate = less? (inclusive? "sle": "slt"):
			greater? (inclusive? "sge": "sgt"): negate? "ne": "eq";
		*cmp = '\0';
	} else if (negate && negate == r_str_trim_head_ro (lhs)) {
		lhs = negate + 1;
		predicate = "eq";
	}
	char *operand = r_egg_mkvar (egg, NULL, lhs, 0);
	LLVMValue a = read_operand (egg, operand, egg->lang.varxs, egg->lang.varsize);
	free (operand);
	operand = r_egg_mkvar (egg, NULL, rhs, 0);
	LLVMValue b = read_operand (egg, operand, egg->lang.varxs, egg->lang.varsize);
	free (operand);
	LLVMValue condition = temporary (state);
	ir (egg, "  %s = icmp %s i64 %s, %s\n", condition.text, predicate, a.text, b.text);
	ir (egg, "  br i1 %s, label %%then.%d, label %%%s\nthen.%d:\n",
		condition.text, state->temporary, dst, state->temporary);
}

static void emit_get_while_end(REgg *egg, RStrBuf *out, const char *operand, const char *label) {
	r_strbuf_set (out, label);
}

static void emit_trap(REgg *egg) {
	LLVMState *state = egg->priv;
	ensure_block (egg);
	ir (egg, "  call void @llvm.trap()\n  unreachable\n");
	state->terminated = true;
	state->trap = true;
}

static void emit_frame_end(REgg *egg, int size, int context) {
	LLVMState *state = egg->priv;
	if (!state->function) {
		emit_error (egg, "block outside a function", "");
		return;
	}
	if (!state->terminated) {
		LLVMType type = state->function->result;
		LLVMValue value = cast_value (egg, read_value (egg, LLVM_RETURN), type, false);
		ir (egg, "  ret %s %s\n", llvm_types[type], value.text);
		state->terminated = true;
	}
}

void egg_llvm_end_function(REgg *egg) {
	LLVMState *state = egg->priv;
	ht_uu_free (state->slots);
	state->slots = NULL;
	state->function = NULL;
}

static void emit_frame(REgg *egg, int size) {
}

static void emit_comment(REgg *egg, const char *format, ...) {
}

static void emit_equ(REgg *egg, const char *key, const char *value) {
}

bool egg_llvm_finish(REgg *egg) {
	LLVMState *state = egg->priv;
	if (state->failed) {
		return false;
	}
	if (state->function) {
		return emit_error (egg, "missing function body for", state->function->name);
	}
	RListIter *iter;
	LLVMFunction *function;
	r_list_foreach (state->functions, iter, function) {
		if (function->syscall_number >= 0) {
			continue;
		}
		if (state->uses_syscall && !strcmp (function->name, "syscall")) {
			return emit_error (egg, "function conflicts with libc syscall symbol", function->name);
		}
		if (!function->external && !function->defined) {
			return emit_error (egg, "undefined function (declare external functions with @extern)", function->name);
		}
		if (function->arity >= 0 && function->arity < function->used_params) {
			return emit_error (egg, "too few arguments for", function->name);
		}
		if (!function->external && !strcmp (function->name, "main") && (function->arity > 0 || function->used_params > 0)) {
			return emit_error (egg, "parameters are unsupported for", function->name);
		}
	}
	// Clang supplies the target triple and data layout.
	r_egg_printf (egg, "; Generated by ragg2\n\n");
	if (!r_buf_append_string (egg->buf, r_strbuf_get (&state->strings))) {
		return false;
	}
	if (state->trap) {
		r_egg_printf (egg, "declare void @llvm.trap()\n");
	}
	if (state->uses_syscall) {
		const char *type = llvm_types[syscall_type (egg)];
		r_egg_printf (egg, "declare %s @syscall(%s, ...)\n\n", type, type);
	}
	r_list_foreach (state->functions, iter, function) {
		if (function->syscall_number >= 0) {
			continue;
		}
		int arity = R_MAX (function->arity, function->used_params);
		const char *linkage = function->external? "declare": function->exported? "define": "define internal";
		r_egg_printf (egg, "%s %s @", linkage, llvm_types[function->result]);
		if (!r_buf_append_string (egg->buf, function->name)) {
			return false;
		}
		r_egg_printf (egg, "(");
		int i;
		for (i = 0; i < arity; i++) {
			LLVMType type = function->external? function->params[i]: LLVM_I64;
			r_egg_printf (egg, "%s%s", i? ", ": "", llvm_types[type]);
			if (!function->external) {
				r_egg_printf (egg, " %%param.%d", i);
			}
		}
		if (function->external) {
			r_egg_printf (egg, ")\n\n");
			continue;
		}
		r_egg_printf (egg, ") {\nentry:\n  %s = alloca i64\n  store i64 0, ptr %s\n", LLVM_RETURN, LLVM_RETURN);
		for (i = 0; i < R_ARRAY_SIZE (llvm_regs); i++) {
			r_egg_printf (egg, "  %s = alloca i64\n  store i64 0, ptr %s\n", llvm_regs[i], llvm_regs[i]);
		}
		for (i = 0; i < arity; i++) {
			r_egg_printf (egg, "  %%arg.%d = alloca i64\n  store i64 %%param.%d, ptr %%arg.%d\n", i, i, i);
		}
		if (!r_buf_append_string (egg->buf, r_strbuf_get (&function->locals))
				|| !r_buf_append_string (egg->buf, r_strbuf_get (&function->body))) {
			return false;
		}
		r_egg_printf (egg, "}\n\n");
	}
	return true;
}

REggEmit emit_llvm = {
	.arch = "llvm",
	.size = 8,
	.retvar = LLVM_RETURN,
	.regs = emit_regs,
	.call = emit_call,
	.jmp = emit_jump,
	.frame = emit_frame,
	.trap = emit_trap,
	.frame_end = emit_frame_end,
	.comment = emit_comment,
	.push_arg = emit_push_arg,
	.set_string = emit_set_string,
	.equ = emit_equ,
	.get_result = emit_get_result,
	.restore_stack = emit_frame,
	.get_var = emit_get_var,
	.get_arg = emit_get_arg,
	.load = emit_load,
	.load_ptr = emit_load_ptr,
	.branch = emit_branch,
	.mathop = emit_mathop,
	.get_while_end = emit_get_while_end,
	.label = emit_label,
	.priv_free = state_free,
};
