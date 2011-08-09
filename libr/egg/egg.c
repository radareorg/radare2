/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>

extern REggEmit emit_x86;
extern REggEmit emit_x64;
extern REggEmit emit_arm;

R_API REgg *r_egg_new () {
	REgg *egg = R_NEW0 (REgg);
	egg->src = r_buf_new ();
	egg->buf = r_buf_new ();
	egg->bin = r_buf_new ();
	egg->emit = &emit_x86;
	egg->syscall = r_syscall_new ();
	egg->rasm = r_asm_new ();
	egg->bits = 0;
	egg->endian = 0;
	return egg;
}

R_API char *r_egg_to_string (REgg *egg) {
	return strdup ((const char *)egg->buf->buf);
}

R_API void r_egg_free (REgg *egg) {
	r_buf_free (egg->src);
	r_buf_free (egg->buf);
	r_buf_free (egg->bin);
	r_asm_free (egg->rasm);
	r_syscall_free (egg->syscall);
	free (egg);
}

R_API void r_egg_reset (REgg *egg) {
	// XXX: memory leak
}

R_API int r_egg_setup(REgg *egg, const char *arch, int bits, int endian, const char *os) {
	egg->emit = NULL;
	egg->os = os? r_str_hash (os): R_EGG_OS_DEFAULT;
	if (!strcmp (arch, "x86")) {
		switch (bits) {
		case 32:
			r_syscall_setup (egg->syscall, arch, os);
			egg->emit = &emit_x86;
			egg->bits = bits;
			break;
		case 64:
			r_syscall_setup (egg->syscall, arch, os);
			egg->emit = &emit_x64;
			egg->bits = bits;
			break;
		}
	} else
	if (!strcmp (arch, "arm")) {
		switch (bits) {
		case 16:
		case 32:
			r_syscall_setup (egg->syscall, arch, os);
			egg->emit = &emit_arm;
			egg->bits = bits;
			egg->endian = endian;
			break;
		}
	}
	return (egg->emit != NULL);
}

R_API int r_egg_include(REgg *egg, const char *file, int format) {
	char *foo = r_file_slurp (file, NULL);
	if (!foo)
		return 0;
	switch (format) {
	case 'r': // raw
		// TODO: append ("\x102030202303203202", n);
		// TODO: r_buf_append_bytes (egg->buf, (const ut8*)foo, strlen (foo));
		break;
	case 'a': // assembly
		r_buf_append_bytes (egg->buf, (const ut8*)foo, strlen (foo));
		break;
	default:
		r_buf_append_bytes (egg->src, (const ut8*)foo, strlen (foo));
	}
	free (foo);
	return 1;
}

R_API void r_egg_load(REgg *egg, const char *code, int format) {
	switch (format) {
	case 'a': // assembly
		r_buf_append_bytes (egg->buf, (const ut8*)code, strlen (code));
		break;
	default:
		r_buf_append_bytes (egg->src, (const ut8*)code, strlen (code));
		break;
	}
}

R_API void r_egg_syscall(REgg *egg, const char *arg, ...) {
	RSyscallItem *item = r_syscall_get (egg->syscall,
		r_syscall_get_num (egg->syscall, arg), -1);
	if (!strcmp (arg, "close")) {
		//egg->emit->syscall_args ();
	}
	egg->emit->syscall (egg, item->num);
}

R_API void r_egg_alloc(REgg *egg, int n) {
	// add esp, n
}

R_API void r_egg_label(REgg *egg, const char *name) {
	r_egg_printf (egg, "%s:\n", name);
}

R_API void r_egg_math (REgg *egg) {//, char eq, const char *vs, char type, const char *sr
	// TODO
	//e->mathop (egg, op, type, eq, p);
}

R_API void r_egg_raw(REgg *egg, const ut8 *b, int len) {
}

// r_egg_block (egg, FRAME | IF | ELSE | ENDIF | FOR | WHILE, sz)
R_API void r_egg_if(REgg *egg, const char *reg, char cmp, int v) {
//	egg->depth++;
}

R_API void r_egg_printf(REgg *egg, const char *fmt, ...) {
	va_list ap;
	int len;
	char buf[1024];
	va_start (ap, fmt);
	len = vsnprintf (buf, sizeof (buf), fmt, ap);
	r_buf_append_bytes (egg->buf, (const ut8*)buf, len);
	va_end (ap);
}

R_API int r_egg_assemble(REgg *egg) {
	if (egg->emit == &emit_x86 || egg->emit == &emit_x64) {
		RAsmCode *asmcode;
		char *code;
		//rasm2
		r_asm_use (egg->rasm, "x86.nz");
		r_asm_set_bits (egg->rasm, egg->bits);
		r_asm_set_big_endian (egg->rasm, 0);
		r_asm_set_syntax (egg->rasm, R_ASM_SYNTAX_INTEL);

		code = r_buf_to_string (egg->buf);
		asmcode = r_asm_massemble (egg->rasm, code);
		if (asmcode && asmcode->len > 0) {
			r_buf_append_bytes (egg->bin, asmcode->buf, asmcode->len);
			// LEAK r_asm_code_free (asmcode);
		} else eprintf ("fail assembling\n");
		free (code);
		return (asmcode != NULL);
	} else
	if (egg->emit == &emit_arm) {
		RAsmCode *asmcode;
		char *code;
		//rasm2
		r_asm_use (egg->rasm, "arm");
		r_asm_set_bits (egg->rasm, egg->bits);
		r_asm_set_big_endian (egg->rasm, egg->endian); // XXX
		r_asm_set_syntax (egg->rasm, R_ASM_SYNTAX_INTEL);

		code = r_buf_to_string (egg->buf);
		asmcode = r_asm_massemble (egg->rasm, code);
		if (asmcode) {
			r_buf_append_bytes (egg->bin, asmcode->buf, asmcode->len);
			// LEAK r_asm_code_free (asmcode);
		}
		free (code);
		return (asmcode != NULL);
	}
	return R_FALSE;
}

R_API int r_egg_compile(REgg *egg) {
	const char *b = (const char *)egg->src->buf;
	if (!b || !egg->emit)
		return R_FALSE;
	for (;*b;b++) {
		r_egg_lang_parsechar (egg, *b);
		// XXX: some parse fail errors are false positives :(
	}
	// TODO: handle errors here
	return R_TRUE;
}

R_API RBuffer *r_egg_get_bin(REgg *egg) {
	// TODO increment reference
	return egg->bin;
}

//R_API int r_egg_dump (REgg *egg, const char *file) { }

R_API char *r_egg_get_source(REgg *egg) {
	return r_buf_to_string (egg->src);
}

R_API char *r_egg_get_assembly(REgg *egg) {
	return r_buf_to_string (egg->buf);
}

R_API void r_egg_append(REgg *egg, const char *src) {
	r_buf_append_bytes (egg->src, (const ut8*)src, strlen (src));
}
