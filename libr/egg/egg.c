/* radare - LGPL - Copyright 2011-2014 - pancake */

#include <r_egg.h>
#include "../config.h"

R_LIB_VERSION (r_egg);

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
	egg->remit = &emit_x86;
	egg->syscall = r_syscall_new ();
	egg->rasm = r_asm_new ();
	egg->bits = 0;
	egg->endian = 0;
	egg->db = sdb_new (NULL, NULL, 0);
	egg->patches = r_list_new ();
	egg->patches->free = (RListFree)r_buf_free;
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
	if (!egg) return;
	r_buf_free (egg->src);
	r_buf_free (egg->buf);
	r_buf_free (egg->bin);
	r_list_free(egg->list);
	r_asm_free (egg->rasm);
	r_syscall_free (egg->syscall);
	sdb_free (egg->db);
	r_list_free (egg->plugins);
	r_list_free (egg->patches);
	free (egg);
}

R_API void r_egg_reset (REgg *egg) {
	r_egg_lang_include_init (egg);
	// TODO: use r_list_purge instead of free/new here
	r_buf_free (egg->src);
	r_buf_free (egg->buf);
	r_buf_free (egg->bin);
	egg->src = r_buf_new ();
	egg->buf = r_buf_new ();
	egg->bin = r_buf_new ();
	r_list_purge (egg->patches);
}

R_API int r_egg_setup(REgg *egg, const char *arch, int bits, int endian, const char *os) {
	egg->remit = NULL;

	egg->os = os? r_str_hash (os): R_EGG_OS_DEFAULT;
//eprintf ("%s -> %x (linux=%x) (darwin=%x)\n", os, egg->os, R_EGG_OS_LINUX, R_EGG_OS_DARWIN);
	// TODO: setup egg->arch for all archs
	if (!strcmp (arch, "x86")) {
		egg->arch = R_SYS_ARCH_X86;
		switch (bits) {
		case 32:
			r_syscall_setup (egg->syscall, arch, os, bits);
			egg->remit = &emit_x86;
			egg->bits = bits;
			break;
		case 64:
			r_syscall_setup (egg->syscall, arch, os, bits);
			egg->remit = &emit_x64;
			egg->bits = bits;
			break;
		}
	} else
	if (!strcmp (arch, "arm")) {
		egg->arch = R_SYS_ARCH_ARM;
		switch (bits) {
		case 16:
		case 32:
			r_syscall_setup (egg->syscall, arch, os, bits);
			egg->remit = &emit_arm;
			egg->bits = bits;
			egg->endian = endian;
			break;
		}
	} else
	if (!strcmp (arch, "trace")) {
		//r_syscall_setup (egg->syscall, arch, os, bits);
		egg->remit = &emit_trace;
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
		//egg->remit->syscall_args ();
	}
	egg->remit->syscall (egg, item->num);
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
	free (out);
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
	RAsmCode *asmcode = NULL;
	char *code = NULL;
	int ret = R_FALSE;
	if (egg->remit == &emit_x86 || egg->remit == &emit_x64) {
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
	} else
	if (egg->remit == &emit_arm) {
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
	}
	free (code);
	ret = (asmcode != NULL);
	r_asm_code_free (asmcode);
	return ret;
}

R_API int r_egg_compile(REgg *egg) {
	const char *b = (const char *)egg->src->buf;
	if (!b || !egg->remit) {
		return R_TRUE;
	}
	// only emit begin if code is found
#if 0
	if (*b)
	if (egg->remit) {
		if (egg->remit->init)
			egg->remit->init (egg);
	}
#endif
	for (; *b; b++) {
		r_egg_lang_parsechar (egg, *b);
		// XXX: some parse fail errors are false positives :(
	}
	if (egg->context>0) {
		eprintf ("ERROR: expected '}' at the end of the file. %d left\n", egg->context);
		return R_FALSE;
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
	return r_sys_run (egg->bin->buf, egg->bin->length);
}

#define R_EGG_FILL_TYPE_TRAP
#define R_EGG_FILL_TYPE_NOP
#define R_EGG_FILL_TYPE_CHAR
#define R_EGG_FILL_TYPE_SEQ
#define R_EGG_FILL_TYPE_SEQ

static inline char *eon(char *n) {
	while (*n && (*n>='0' && *n<='9')) n++;
	return n;
}

R_API int r_egg_padding (REgg *egg, const char *pad) {
	int n;
	ut8* xx, byte;
	char *q, *p, *o = strdup (pad);
	// parse pad string
	for (p=o; *p; ) {
		char t, f = *p++;
		q = eon (p);
		t = *q;
		*q = 0;
		n = atoi (p);
		*q = t;
		p = q;
		if (n<1) {
			eprintf ("Invalid padding length at %d\n", n);
			free (o);
			return R_FALSE;
		}
		switch (f) {
		case 's': case 'S': byte = 0; break;
		case 'n': case 'N': byte = 0x90; break;
		case 'a': case 'A': byte = 'A'; break;
		case 't': case 'T': byte = 0xcc; break;
		default:
			eprintf ("Invalid padding format (%c)\n", *p);
			free (o);
			return R_FALSE;
		}

		xx = malloc (n);
		if (!xx) {
			free (o);
			return R_FALSE;
		}
		if (byte == 0) {
			// TODO: add support for word-sized sequences
			int i;
			for (i=0; i<n; i++)
				xx[i] = i;
		} else memset (xx, byte, n);
		if (f>='a' && f<='z')
			r_buf_prepend_bytes (egg->bin, xx, n);
		else r_buf_append_bytes (egg->bin, xx, n);
		free (xx);
	}
	free (o);
	return R_TRUE;
}

R_API void r_egg_fill(REgg *egg, int pos, int type, int argc, int length) {
	// TODO
}

R_API void r_egg_option_set(REgg *egg, const char *key, const char *val) {
	sdb_set (egg->db, key, val, 0);
}

R_API char *r_egg_option_get(REgg *egg, const char *key) {
	return sdb_get (egg->db, key, NULL);
}

R_API int r_egg_shellcode(REgg *egg, const char *name) {
	REggPlugin *p;
	RListIter *iter;
	RBuffer *b;
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_SHELLCODE && !strcmp (name, p->name)) {
			b = p->build (egg);
			if (b == NULL) {
				eprintf ("%s Encoder has failed\n", p->name);
				return R_FALSE;
			}
			r_egg_raw (egg, b->buf, b->length);
			r_buf_free (b);
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_egg_encode(REgg *egg, const char *name) {
	REggPlugin *p;
	RListIter *iter;
	RBuffer *b;
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_ENCODER && !strcmp (name, p->name)) {
			b = p->build (egg);
			r_buf_free (egg->bin);
			egg->bin = b;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_egg_patch(REgg *egg, int off, const ut8 *buf, int len) {
	RBuffer *b = r_buf_new ();
	if (!b) return R_FALSE;
	if (!r_buf_set_bytes (b, buf, len)) {
		r_buf_free (b);
		return R_FALSE;
	}
	b->cur = off;
	r_list_append (egg->patches, b);
	return R_TRUE;
}

R_API void r_egg_finalize(REgg *egg) {
	RBuffer *b;
	RListIter *iter;
	if (!egg->bin->buf)
		egg->bin = r_buf_new ();
	r_list_foreach (egg->patches, iter, b) {
		if (b->cur <0) {
			r_buf_append_bytes (egg->bin, b->buf, b->length);
		} else {
			// TODO: use r_buf_cpy_buf or what
			if (b->length+b->cur > egg->bin->length) {
				eprintf ("Fuck this shit. Cant patch outside\n");
				return;
			}
			memcpy (egg->bin->buf + b->cur, b->buf, b->length);
		}
	}
}

R_API void r_egg_pattern(REgg *egg, int size) {
	char *ret = r_debruijn_pattern ((int)size, 0, NULL);
	if (ret) {
		r_buf_prepend_bytes (egg->bin, (const ut8*)ret, strlen (ret));
		free (ret);
	} else eprintf ("Invalid debruijn pattern length.\n");
}
