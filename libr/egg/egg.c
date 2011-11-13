/* radare - LGPL - Copyright 2011 pancake<@nopcode.org> */
#include <r_egg.h>
#include "../config.h"

// TODO: must be plugins
extern REggEmit emit_x86;
extern REggEmit emit_x64;
extern REggEmit emit_arm;
extern REggEmit emit_trace;

static REggPlugin *egg_static_plugins[] = 
	{ R_EGG_STATIC_PLUGINS };

R_API REgg *r_egg_new () {
	int i;
	REgg *egg = R_NEW0 (REgg);
	egg->src = r_buf_new ();
	egg->buf = r_buf_new ();
	egg->bin = r_buf_new ();
	egg->emit = &emit_x86;
	egg->syscall = r_syscall_new ();
	egg->rasm = r_asm_new ();
	egg->bits = 0;
	egg->endian = 0;
	egg->pair = r_pair_new ();
	egg->plugins = r_list_new ();
	for (i=0; egg_static_plugins[i]; i++) {
		REggPlugin *static_plugin = R_NEW (REggPlugin);
		memcpy (static_plugin, egg_static_plugins[i], sizeof (REggPlugin));
		r_egg_add (egg, static_plugin);
	}
	return egg;
}

R_API int r_egg_add (REgg *a, REggPlugin *foo) {
	RListIter *iter;
	RAsmPlugin *h;
	// TODO: cache foo->name length and use memcmp instead of strcmp
	if (!foo->name)
		return R_FALSE;
	//if (foo->init)
	//	foo->init (a->user);
	r_list_foreach (a->plugins, iter, h)
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	r_list_append (a->plugins, foo);
	return R_TRUE;
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
	r_egg_lang_include_init (egg);
	r_buf_free (egg->src);
	r_buf_free (egg->buf);
	egg->src = r_buf_new ();
	egg->buf = r_buf_new ();
}

R_API int r_egg_setup(REgg *egg, const char *arch, int bits, int endian, const char *os) {
	egg->emit = NULL;
	egg->os = os? r_str_hash (os): R_EGG_OS_DEFAULT;
	if (!strcmp (arch, "x86")) {
		switch (bits) {
		case 32:
			r_syscall_setup (egg->syscall, arch, os, bits);
			egg->emit = &emit_x86;
			egg->bits = bits;
			break;
		case 64:
			r_syscall_setup (egg->syscall, arch, os, bits);
			egg->emit = &emit_x64;
			egg->bits = bits;
			break;
		}
	} else
	if (!strcmp (arch, "arm")) {
		switch (bits) {
		case 16:
		case 32:
			r_syscall_setup (egg->syscall, arch, os, bits);
			egg->emit = &emit_arm;
			egg->bits = bits;
			egg->endian = endian;
			break;
		}
	} else
	if (!strcmp (arch, "trace")) {
		//r_syscall_setup (egg->syscall, arch, os, bits);
		egg->emit = &emit_trace;
		egg->bits = bits;
		egg->endian = endian;
	}
	return 0;
}

R_API int r_egg_include(REgg *egg, const char *file, int format) {
	int sz;
	const ut8 *foo = (const ut8*)r_file_slurp (file, &sz);
	if (!foo)
		return 0;
// XXX: format breaks compiler layers
	switch (format) {
	case 'r': // raw
		r_egg_raw (egg, foo, sz);
		break;
	case 'a': // assembly
		r_buf_append_bytes (egg->buf, foo, sz);
		break;
	default:
		r_buf_append_bytes (egg->src, foo, sz);
	}
	free ((void *)foo);
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

R_API int r_egg_raw(REgg *egg, const ut8 *b, int len) {
	char *out;
	int outlen = (len*2)+1;
	out = malloc (outlen);
	if (!out) return R_FALSE;
	r_hex_bin2str (b, len, out);
	r_buf_append_bytes (egg->buf, (const ut8*)".hex ", 5);
	r_buf_append_bytes (egg->buf, (const ut8*)out, outlen);
	r_buf_append_bytes (egg->buf, (const ut8*)"\n", 1);
	return R_TRUE;
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
		if (asmcode) {
			if (asmcode->len > 0) 
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
	// only emit begin if code is found
	if (*b)
	if (egg->emit) {
		if (egg->emit->init)
			egg->emit->init (egg);
	}
	for (; *b; b++) {
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

/* JIT : TODO: accept arguments here */
R_API int r_egg_run(REgg *egg) {
	int ret, (*cb)();
	ut8 *ptr = malloc (4096);
	ut8* shellcode = egg->bin->buf;
	if (!ptr) return R_FALSE;
	memcpy (ptr, shellcode, 4096);
	r_mem_protect (ptr, 4096, "rx");
	r_mem_protect (ptr, 4096, "rwx"); // try, ignore if fail
	cb = (void*)ptr;
	ret = cb ();
	free (ptr);
	return ret;
}

#define R_EGG_FILL_TYPE_TRAP
#define R_EGG_FILL_TYPE_NOP
#define R_EGG_FILL_TYPE_CHAR
#define R_EGG_FILL_TYPE_SEQ
#define R_EGG_FILL_TYPE_SEQ

R_API void r_egg_fill(REgg *egg, int pos, int type, int argc, int length) {
}

// functions that manipulate the compile() buffer
//-----------------------------------------------
#if 0
 - fill traps
 - fill nops
 - fill char
 - fill sequence 01 02 03..
 - fill printable seq

- encoder
#endif

R_API void r_egg_option_set(REgg *egg, const char *key, const char *val) {
	return r_pair_set (egg->pair, key, val);
}

R_API char *r_egg_option_get(REgg *egg, const char *key) {
	return r_pair_get (egg->pair, key);
}

R_API int r_egg_shellcode(REgg *egg, const char *name) {
	REggPlugin *p;
	RListIter *iter;
	RBuffer *b;
	r_list_foreach (egg->plugins, iter, p) {
		if (!strcmp (name, p->name)) {
			b = p->build (egg);
			r_egg_raw (egg, b->buf, b->length);
			r_buf_free (b);
			return R_TRUE;
		}
	}
	return R_FALSE;
}
