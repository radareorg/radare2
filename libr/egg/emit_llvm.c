/* radare - LGPL - Copyright 2026 - pancake */

#include <r_egg.h>

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
	char *operand;
	int modifier;
	int size;
} LLVMArg;

typedef struct {
	char *name;
	RStrBuf body;
	RStrBuf locals;
	LLVMType result;
	LLVMType params[LLVM_MAX_ARGS];
	int arity;
	int used_params;
	bool defined;
	bool external;
	bool exported;
} LLVMFunction;

typedef struct {
	RList *functions;
	Sdb *symbols; // function pointers and "loop.<end label>" back-edges
	HtUU *slots;
	RStrBuf strings;
	RStrBuf assembly;
	LLVMFunction *function;
	LLVMArg args[LLVM_MAX_ARGS];
	int temporary;
	int string_id;
	bool terminated;
	bool trap;
	bool uses_syscall;
	bool asm_ready;
} LLVMState;

static void function_free(void *data) {
	LLVMFunction *function = data;
	free (function->name);
	r_strbuf_fini (&function->body);
	r_strbuf_fini (&function->locals);
	free (function);
}

static void *state_new(REgg *egg) {
	LLVMState *state = R_NEW0 (LLVMState);
	state->functions = r_list_newf (function_free);
	state->symbols = sdb_new0 ();
	state->slots = ht_uu_new0 ();
	return state;
}

static void state_free(void *data) {
	LLVMState *state = data;
	int i;
	for (i = 0; i < LLVM_MAX_ARGS; i++) {
		free (state->args[i].operand);
	}
	r_list_free (state->functions);
	sdb_free (state->symbols);
	ht_uu_free (state->slots);
	r_strbuf_fini (&state->strings);
	r_strbuf_fini (&state->assembly);
	free (state);
}

static void emit_error(REgg *egg, const char *message, const char *detail) {
	if (!egg->lang.failed) {
		R_LOG_ERROR ("%s:%d: LLVM: %s '%s'", r_str_get (egg->lang.file), egg->lang.line, message, r_str_get (detail));
		egg->lang.failed = true;
	}
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
		function->result = !strcmp (name, "main")? LLVM_I32: LLVM_I64;
		r_list_append (state->functions, function);
		sdb_ptr_set (state->symbols, name, function, 0);
	}
	return function;
}

static void emit_function(REgg *egg, const char *name, const char *kind) {
	LLVMState *state = egg->priv;
	LLVMFunction *function = find_function (egg, name);
	if (*kind && strcmp (kind, "global")) {
		emit_error (egg, "unsupported directive", kind);
	} else if (function && (function->defined || function->external)) {
		emit_error (egg, "unexpected function definition", name);
	} else if (function) {
		function->defined = true;
		function->exported = *kind;
		state->function = function;
		state->temporary = 0;
		state->terminated = false;
		ht_uu_free (state->slots);
		state->slots = ht_uu_new0 ();
	}
}

static LLVMType parse_type(RStrs name) {
	int i;
	for (i = LLVM_VOID; i <= LLVM_PTR; i++) {
		if (r_strs_equals_str (name, llvm_types[i])) {
			return i;
		}
	}
	return LLVM_INVALID;
}

static void emit_declare(REgg *egg, const char *name, const char *signature) {
	LLVMFunction *function = find_function (egg, name);
	if (!function) {
		return;
	}
	if (function->defined || function->external || function->arity >= 0) {
		emit_error (egg, "extern declaration must precede uses of", name);
		return;
	}
	RStrs sig = r_strs_from (signature), tok;
	int count = 0;
	while (r_strs_next_token (&sig, ",", &tok)) {
		r_strs_trim (&tok);
		LLVMType type = parse_type (tok);
		if (!type || (count && type == LLVM_VOID) || count > LLVM_MAX_ARGS) {
			count = 0;
			break;
		}
		*(count? &function->params[count - 1]: &function->result) = type;
		count++;
	}
	if (!count) {
		emit_error (egg, "invalid extern signature for", name);
		return;
	}
	function->arity = count - 1;
	function->external = true;
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

static void ensure_block(REgg *egg) {
	LLVMState *state = egg->priv;
	if (!egg->context) {
		emit_error (egg, "instruction outside a function", "");
	} else if (state->terminated && state->function) {
		r_strbuf_appendf (&state->function->body, "dead.%d:\n", ++state->temporary);
		state->terminated = false;
	}
}

// pending `: lines` are assembled together and placed before the next IR instruction
static void flush_assembly(REgg *egg) {
	LLVMState *state = egg->priv;
	if (r_strbuf_is_empty (&state->assembly) || !state->function) {
		return;
	}
	char *source = r_strbuf_drain_nofree (&state->assembly);
	RAsm *assembler = egg->rasm;
	if (!state->asm_ready) {
		char *arch = r_egg_option_get (egg, "llvm.asm.arch");
		r_asm_set_bits (assembler, egg->bits);
		r_asm_set_big_endian (assembler, egg->endian);
		r_arch_config_set_syntax (assembler->config, R_ARCH_SYNTAX_INTEL);
		state->asm_ready = r_asm_use (assembler, R_STR_ISNOTEMPTY (arch)? arch: R_SYS_ARCH);
		free (arch);
	}
	r_asm_set_pc (assembler, 0);
	RAsmCode *code = state->asm_ready? r_asm_assemble (assembler, source): NULL;
	if (code && code->len > 0) {
		ensure_block (egg);
		RStrBuf *body = &state->function->body;
		r_strbuf_append (body, "  call void asm sideeffect \".byte ");
		int i;
		for (i = 0; i < code->len; i++) {
			r_strbuf_appendf (body, "%s0x%02x", i? ", ": "", code->bytes[i]);
		}
		r_strbuf_appendf (body, "\", \"%s\"()\n", assembly_clobbers (assembler->config->arch, egg->bits));
	} else {
		emit_error (egg, "cannot assemble inline code (set llvm.asm.arch) for", assembler->config->arch);
	}
	r_asm_code_free (code);
	free (source);
}

static void emit_raw(REgg *egg, const char *text) {
	LLVMState *state = egg->priv;
	const char *line = r_str_trim_head_ro (text);
	if (!*line) {
		return;
	}
	if (!egg->context) {
		emit_error (egg, "unsupported assembly outside a function", line);
	} else {
		r_strbuf_append (&state->assembly, line);
	}
}

static void ir(REgg *egg, const char *format, ...) R_PRINTF_CHECK(2, 3);

static void ir(REgg *egg, const char *format, ...) {
	LLVMState *state = egg->priv;
	if (!state->function) {
		emit_error (egg, "instruction outside a function", "");
		return;
	}
	flush_assembly (egg);
	va_list ap;
	va_start (ap, format);
	r_strbuf_vappendf (&state->function->body, format, ap);
	va_end (ap);
}

static LLVMValue temporary(LLVMState *state) {
	LLVMValue value;
	snprintf (value.text, sizeof (value.text), "%%t%d", ++state->temporary);
	return value;
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

static void emit_get_local(REgg *egg, RStrBuf *out, int kind, int idx) {
	LLVMState *state = egg->priv;
	LLVMFunction *function = state->function;
	if (!function || idx < 0 || (kind == 'a' && idx >= LLVM_MAX_ARGS)) {
		emit_error (egg, "invalid variable", "");
		return;
	}
	if (kind == 'a') {
		function->used_params = R_MAX (function->used_params, idx + 1);
		r_strbuf_setf (out, "%%arg.%d", idx);
		return;
	}
	r_strbuf_setf (out, "%%%s.%d", kind == 'f'? "fix": "local", idx);
	const ut64 key = ((ut64)idx << 1) | (kind == 'f');
	if (!ht_uu_find (state->slots, key, NULL)) {
		ht_uu_insert (state->slots, key, 1);
		r_strbuf_appendf (&function->locals, "  %s = alloca i64\n", r_strbuf_get (out));
	}
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
	if (!destination) {
		store_value (egg, LLVM_RETURN, value);
		return;
	}
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

static void emit_set_string(REgg *egg, const char *destination, RStrs string) {
	const int length = r_strs_len (string);
	LLVMState *state = egg->priv;
	ensure_block (egg);
	const int id = state->string_id++;
	RStrBuf *strings = &state->strings;
	r_strbuf_appendf (strings, "@.egg.str.%d = private unnamed_addr constant [%d x i8] c\"", id, length + 1);
	int i;
	for (i = 0; i < length; i++) {
		const ut8 byte = string.a[i];
		if (byte >= 32 && byte < 127 && byte != '"' && byte != '\\') {
			r_strbuf_append_n (strings, string.a + i, 1);
		} else {
			r_strbuf_appendf (strings, "\\%02X", byte);
		}
	}
	r_strbuf_append (strings, "\\00\"\n");
	char *slot = r_egg_mkvar (egg, r_strs_from (destination), 0);
	LLVMValue value = temporary (state);
	ir (egg, "  %s = ptrtoint ptr @.egg.str.%d to i64\n", value.text, id);
	store_value (egg, slot, value);
	free (slot);
}

// arguments are evaluated when the call is emitted, so if/while conditions are never loaded
static void emit_push_arg(REgg *egg, int modifier, int index, const char *operand) {
	LLVMState *state = egg->priv;
	if (index < 1 || index > LLVM_MAX_ARGS) {
		emit_error (egg, "too many call arguments for", egg->lang.callname);
		return;
	}
	LLVMArg *arg = &state->args[index - 1];
	free (arg->operand);
	arg->operand = strdup (operand);
	arg->modifier = modifier;
	arg->size = egg->lang.varsize;
}

static LLVMValue arg_value(REgg *egg, int index, LLVMType type) {
	LLVMArg *arg = &((LLVMState *)egg->priv)->args[index];
	return cast_value (egg, read_operand (egg, arg->operand, arg->modifier, arg->size), type, false);
}

static void emit_syscall_args(REgg *egg, int nargs) {
}

static char *emit_syscall(REgg *egg, int nargs) {
	LLVMState *state = egg->priv;
	LLVMType result_type = syscall_type (egg);
	char *number = r_egg_mkvar (egg, r_strs_from (".arg"), 0);
	char *end = NULL;
	const long value = number? strtol (number, &end, 0): -1;
	if (!result_type || (egg->bits != 32 && egg->bits != 64)) {
		emit_error (egg, "syscall requires a 32- or 64-bit Linux or macOS target", egg->lang.callname);
	} else if (end == number || *r_str_trim_head_ro (end) || value < 0 || value > ST32_MAX || nargs > LLVM_MAX_ARGS) {
		emit_error (egg, "invalid syscall", number);
	} else {
		LLVMType word_type = egg->bits == 32? LLVM_I32: LLVM_I64;
		const char *type = llvm_types[result_type];
		ensure_block (egg);
		LLVMValue args[LLVM_MAX_ARGS];
		int i;
		for (i = 0; i < nargs; i++) {
			args[i] = arg_value (egg, i, word_type);
		}
		LLVMValue result = temporary (state);
		ir (egg, "  %s = call %s (%s, ...) @syscall(%s %ld", result.text, type, type, type, value);
		for (i = nargs - 1; i >= 0; i--) {
			ir (egg, ", %s %s", llvm_types[word_type], args[i].text);
		}
		ir (egg, ")\n");
		store_value (egg, LLVM_RETURN, cast_value (egg, result, result_type, true));
		state->uses_syscall = true;
	}
	free (number);
	return strdup ("");
}

static void emit_call(REgg *egg, const char *name, int indirect) {
	LLVMState *state = egg->priv;
	const int nargs = egg->lang.nargs;
	ensure_block (egg);
	if (indirect || nargs > LLVM_MAX_ARGS) {
		emit_error (egg, "unsupported call to", name);
		return;
	}
	LLVMFunction *target = find_function (egg, name);
	if (!target || egg->lang.failed) {
		return;
	}
	if (target->arity >= 0 && target->arity != nargs) {
		emit_error (egg, "inconsistent argument count for", name);
		return;
	}
	target->arity = nargs;
	LLVMValue args[LLVM_MAX_ARGS];
	int i;
	for (i = 0; i < nargs; i++) {
		args[i] = arg_value (egg, i, target->external? target->params[nargs - 1 - i]: LLVM_I64);
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
		ir (egg, "%s%s %s", i? ", ": "", llvm_types[target->external? target->params[i]: LLVM_I64], args[nargs - 1 - i].text);
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
	flush_assembly (egg);
	if (!state->terminated) {
		ir (egg, "  br label %%%s\n", label);
		state->terminated = true;
	}
}

static void emit_label(REgg *egg, const char *name) {
	LLVMState *state = egg->priv;
	char *key = r_str_newf ("loop.%s", name);
	const char *loop = sdb_const_get (state->symbols, key, NULL);
	emit_jump (egg, loop? loop: name, 0);
	free (key);
	ir (egg, "%s:\n", name);
	state->terminated = false;
}

static void emit_get_while_end(REgg *egg, RStrBuf *out, const char *operand, const char *label) {
	LLVMState *state = egg->priv;
	char *end = r_str_replace (r_str_newf ("loop.%s", label), "__begin_", "__end_", 0);
	sdb_set (state->symbols, end, label, 0);
	free (end);
}

static void emit_while_end(REgg *egg, const char *label) {
	emit_error (egg, "unsupported do-while loop", label);
}

static void emit_branch(REgg *egg, const REggCond *cond, int size, const char *dst) {
	LLVMState *state = egg->priv;
	const char *predicate;
	switch (cond->cmp) {
	case '<': predicate = cond->inclusive? "sle": "slt"; break;
	case '>': predicate = cond->inclusive? "sge": "sgt"; break;
	case '=': predicate = cond->negate? "ne": "eq"; break;
	default: predicate = cond->negate? "eq": "ne"; break;
	}
	LLVMValue values[2];
	const RStrs operands[2] = { cond->lhs, cond->rhs };
	int i;
	for (i = 0; i < 2; i++) {
		char *operand = r_egg_mkvar (egg, operands[i], 0);
		values[i] = read_operand (egg, operand, egg->lang.varxs, egg->lang.varsize);
		free (operand);
	}
	LLVMValue condition = temporary (state);
	ir (egg, "  %s = icmp %s i64 %s, %s\n", condition.text, predicate, values[0].text, values[1].text);
	ir (egg, "  br i1 %s, label %%then.%d, label %%%s\nthen.%d:\n",
		condition.text, state->temporary, dst, state->temporary);
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
	flush_assembly (egg);
	if (state->function && !state->terminated) {
		LLVMType type = state->function->result;
		LLVMValue value = cast_value (egg, read_value (egg, LLVM_RETURN), type, false);
		ir (egg, "  ret %s %s\n", llvm_types[type], value.text);
		state->terminated = true;
	}
}

static void emit_frame(REgg *egg, int size) {
}

static void emit_comment(REgg *egg, const char *format, ...) {
}

static void emit_equ(REgg *egg, const char *key, const char *value) {
}

static bool emit_finalize(REgg *egg) {
	LLVMState *state = egg->priv;
	RListIter *iter;
	LLVMFunction *function;
	r_list_foreach (state->functions, iter, function) {
		const char *error = (state->uses_syscall && !strcmp (function->name, "syscall"))? "function conflicts with libc syscall symbol"
			: (!function->external && !function->defined)? "undefined function (declare external functions with @extern)"
			: (function->arity >= 0 && function->arity < function->used_params)? "too few arguments for"
			: (function->defined && !strcmp (function->name, "main") && (function->arity > 0 || function->used_params > 0))? "parameters are unsupported for"
			: NULL;
		if (error) {
			emit_error (egg, error, function->name);
			return false;
		}
	}
	// Clang supplies the target triple and data layout.
	RStrBuf *out = r_strbuf_new ("; Generated by ragg2\n\n");
	r_strbuf_append (out, r_strbuf_get (&state->strings));
	if (state->trap) {
		r_strbuf_append (out, "declare void @llvm.trap()\n");
	}
	if (state->uses_syscall) {
		const char *type = llvm_types[syscall_type (egg)];
		r_strbuf_appendf (out, "declare %s @syscall(%s, ...)\n\n", type, type);
	}
	r_list_foreach (state->functions, iter, function) {
		const int arity = R_MAX (function->arity, function->used_params);
		const char *linkage = function->external? "declare": function->exported? "define": "define internal";
		r_strbuf_appendf (out, "%s %s @%s(", linkage, llvm_types[function->result], function->name);
		int i;
		for (i = 0; i < arity; i++) {
			LLVMType type = function->external? function->params[i]: LLVM_I64;
			r_strbuf_appendf (out, "%s%s", i? ", ": "", llvm_types[type]);
			if (!function->external) {
				r_strbuf_appendf (out, " %%param.%d", i);
			}
		}
		if (function->external) {
			r_strbuf_append (out, ")\n\n");
			continue;
		}
		r_strbuf_appendf (out, ") {\nentry:\n  %s = alloca i64\n  store i64 0, ptr %s\n", LLVM_RETURN, LLVM_RETURN);
		for (i = 0; i < R_ARRAY_SIZE (llvm_regs); i++) {
			r_strbuf_appendf (out, "  %s = alloca i64\n  store i64 0, ptr %s\n", llvm_regs[i], llvm_regs[i]);
		}
		for (i = 0; i < arity; i++) {
			r_strbuf_appendf (out, "  %%arg.%d = alloca i64\n  store i64 %%param.%d, ptr %%arg.%d\n", i, i, i);
		}
		r_strbuf_appendf (out, "%s%s}\n\n", r_strbuf_get (&function->locals), r_strbuf_get (&function->body));
	}
	// anything printed by the shared parser is native assembly text, the module replaces it
	const bool ok = r_buf_set_bytes (egg->buf, (const ut8 *)r_strbuf_get (out), r_strbuf_length (out));
	r_strbuf_free (out);
	return ok;
}

REggEmit emit_llvm = {
	.arch = "llvm",
	.size = 8,
	.retvar = LLVM_RETURN,
	.regs = emit_regs,
	.call = emit_call,
	.jmp = emit_jump,
	.frame = emit_frame,
	.syscall = emit_syscall,
	.trap = emit_trap,
	.frame_end = emit_frame_end,
	.comment = emit_comment,
	.push_arg = emit_push_arg,
	.set_string = emit_set_string,
	.equ = emit_equ,
	.get_result = emit_get_result,
	.restore_stack = emit_frame,
	.syscall_args = emit_syscall_args,
	.while_end = emit_while_end,
	.load = emit_load,
	.load_ptr = emit_load_ptr,
	.branch = emit_branch,
	.mathop = emit_mathop,
	.get_while_end = emit_get_while_end,
	.label = emit_label,
	.function = emit_function,
	.declare = emit_declare,
	.raw = emit_raw,
	.get_local = emit_get_local,
	.finalize = emit_finalize,
	.priv_new = state_new,
	.priv_free = state_free,
};
