/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_egg.h>
#include <config.h>

R_LIB_VERSION(r_egg);

// TODO: must be plugins
extern REggEmit emit_x86;
extern REggEmit emit_x64;
extern REggEmit emit_arm;
extern REggEmit emit_a64;
extern REggEmit emit_esil;
extern REggEmit emit_trace;

static REggPlugin *egg_static_plugins[] = { R_EGG_STATIC_PLUGINS };

struct egg_patch_t {
	RBuffer *b;
	int off;
};

void egg_patch_free(void *p) {
	struct egg_patch_t *ep = (struct egg_patch_t *)p;
	if (ep) {
		r_buf_free (ep->b);
		free (ep);
	}
}

R_API REgg *r_egg_new(void) {
	int i;
	REgg *egg = R_NEW0 (REgg);
	if (!egg) {
		return NULL;
	}
	egg->src = r_buf_new ();
	if (!egg->src) {
		goto beach;
	}
	egg->buf = r_buf_new ();
	if (!egg->buf) {
		goto beach;
	}
	egg->bin = r_buf_new ();
	if (!egg->bin) {
		goto beach;
	}
	egg->remit = &emit_x86;
	egg->syscall = r_syscall_new ();
	if (!egg->syscall) {
		goto beach;
	}
	egg->rasm = r_asm_new ();
	if (!egg->rasm) {
		goto beach;
	}
#if 0
	egg->anal = r_anal_new ();
	if (!egg->anal) {
		goto beach;
	}
	r_anal_bind (egg->anal, &egg->rasm->analb);
#endif
	egg->bits = 0;
	egg->endian = 0;
	egg->db = sdb_new (NULL, NULL, 0);
	if (!egg->db) {
		goto beach;
	}
	egg->patches = r_list_newf (egg_patch_free);
	if (!egg->patches) {
		goto beach;
	}
	egg->plugins = r_list_new ();
	for (i = 0; egg_static_plugins[i]; i++) {
		r_egg_plugin_add (egg, egg_static_plugins[i]);
	}
	return egg;

beach:
	r_egg_free (egg);
	return NULL;
}

R_API bool r_egg_plugin_add(REgg *a, REggPlugin *foo) {
	R_RETURN_VAL_IF_FAIL (a && foo, false);
	RListIter *iter;
	// TODO: cache foo->name length and use memcmp instead of strcmp
	if (!foo->meta.name) {
		return false;
	}
	REggPlugin *h;
	r_list_foreach (a->plugins, iter, h) {
		if (!strcmp (h->meta.name, foo->meta.name)) {
			return false;
		}
	}
	r_list_append (a->plugins, foo);
	return true;
}

R_API bool r_egg_plugin_remove(REgg *a, REggPlugin *plugin) {
	// XXX TODO
	return true;
}

R_API char *r_egg_tostring(REgg *egg) {
	R_RETURN_VAL_IF_FAIL (egg, NULL);
	return r_buf_tostring (egg->buf);
}

R_API void r_egg_free(REgg *egg) {
	if (egg) {
		r_buf_free (egg->src);
		r_buf_free (egg->buf);
		r_buf_free (egg->bin);
		r_list_free (egg->list);
		r_asm_free (egg->rasm);
		//	r_anal_free (egg->anal);
		r_syscall_free (egg->syscall);
		sdb_free (egg->db);
		r_list_free (egg->plugins);
		r_list_free (egg->patches);
		r_egg_lang_free (egg);
		free (egg);
	}
}

R_API void r_egg_reset(REgg *egg) {
	R_RETURN_IF_FAIL (egg);
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

// TODO: use RArchConfig instead
R_API bool r_egg_setup(REgg *egg, const char *arch, int bits, int endian, const char *os) {
	R_RETURN_VAL_IF_FAIL (egg && arch, false);
	const char *asmcpu = NULL; // TODO
	egg->remit = NULL;

	egg->os = os? r_str_hash (os): R_EGG_OS_DEFAULT;
	// eprintf ("%s -> %x (linux=%x) (darwin=%x)\n", os, egg->os, R_EGG_OS_LINUX, R_EGG_OS_DARWIN);
	//  TODO: setup egg->arch for all archs
	if (!strcmp (arch, "x86")) {
		egg->arch = R_SYS_ARCH_X86;
		switch (bits) {
		case 32:
			r_syscall_setup (egg->syscall, arch, bits, asmcpu, os);
			egg->remit = &emit_x86;
			egg->bits = bits;
			break;
		case 64:
			r_syscall_setup (egg->syscall, arch, bits, asmcpu, os);
			egg->remit = &emit_x64;
			egg->bits = bits;
			break;
		}
	} else if (!strcmp (arch, "esil")) {
		egg->arch = R_SYS_ARCH_ESIL;
		r_syscall_setup (egg->syscall, arch, bits, asmcpu, os);
		egg->remit = &emit_esil;
	} else if (!strcmp (arch, "arm")) {
		egg->arch = R_SYS_ARCH_ARM;
		switch (bits) {
		case 16:
		case 32:
			r_syscall_setup (egg->syscall, arch, bits, asmcpu, os);
			egg->remit = &emit_arm;
			egg->bits = bits;
			egg->endian = endian;
			break;
		case 64:
			r_syscall_setup (egg->syscall, arch, bits, asmcpu, os);
			egg->remit = &emit_a64;
			egg->bits = bits;
			egg->endian = endian;
			break;
		}
	} else if (!strcmp (arch, "trace")) {
		// r_syscall_setup (egg->syscall, arch, os, bits);
		egg->remit = &emit_trace;
		egg->bits = bits;
		egg->endian = endian;
	}
	return true;
}

R_API bool r_egg_include_str(REgg *egg, const char *arg) {
	r_buf_append_bytes (egg->src, (const ut8 *)arg, strlen (arg));
	return true;
}

R_API bool r_egg_include(REgg *egg, const char *file, int format) {
	R_RETURN_VAL_IF_FAIL (egg && file, false);
	size_t sz;
	const ut8 *foo = (const ut8 *)r_file_slurp (file, &sz);
	if (!foo) {
		return false;
	}
	// XXX: format breaks compiler layers
	switch (format) {
	case 'r': // raw
		r_egg_raw (egg, foo, (int)sz);
		break;
	case 'a': // assembly
		r_buf_append_bytes (egg->buf, foo, (ut64)sz);
		break;
	default:
		r_buf_append_bytes (egg->src, foo, (ut64)sz);
		break;
	}
	free ((void *)foo);
	return true;
}

R_API void r_egg_load(REgg *egg, const char *code, int format) {
	R_RETURN_IF_FAIL (egg && code);
	switch (format) {
	case 'a': // assembly
		r_buf_append_bytes (egg->buf, (const ut8 *)code, strlen (code));
		break;
	default:
		r_buf_append_bytes (egg->src, (const ut8 *)code, strlen (code));
		break;
	}
}

R_API void r_egg_syscall(REgg *egg, const char *arg, ...) {
	R_RETURN_IF_FAIL (egg);
	RSyscallItem *item = r_syscall_get (egg->syscall,
		r_syscall_get_num (egg->syscall, arg), -1);
	if (!strcmp (arg, "close")) {
		// egg->remit->syscall_args ();
	}
	if (!item) {
		return;
	}
	egg->remit->syscall (egg, item->num);
	r_syscall_item_free (item);
}

R_API void r_egg_alloc(REgg *egg, int n) {
	// add esp, n
}

R_API void r_egg_label(REgg *egg, const char *name) {
	r_egg_printf (egg, "%s:\n", name);
}

R_API void r_egg_math(REgg *egg) { //, char eq, const char *vs, char type, const char *sr
	// TODO
	// e->mathop (egg, op, type, eq, p);
}

R_API bool r_egg_raw(REgg *egg, const ut8 *b, int len) {
	R_RETURN_VAL_IF_FAIL (egg && b, false);
	int outlen = len * 2; // two hexadecimal digits per byte
	char *out = malloc (outlen + 1);
	if (!out) {
		return false;
	}
	(void)r_hex_bin2str (b, len, out);
	r_buf_append_bytes (egg->buf, (const ut8 *)".hex ", 5);
	r_buf_append_bytes (egg->buf, (const ut8 *)out, outlen);
	r_buf_append_bytes (egg->buf, (const ut8 *)"\n", 1);
	free (out);
	return true;
}

static bool r_egg_raw_prepend(REgg *egg, const ut8 *b, int len) {
	R_RETURN_VAL_IF_FAIL (egg && b, false);
	int outlen = len * 2; // two hexadecimal digits per byte
	char *out = malloc (outlen + 1);
	if (!out) {
		return false;
	}
	r_hex_bin2str (b, len, out);
	r_buf_prepend_bytes (egg->buf, (const ut8 *)"\n", 1);
	r_buf_prepend_bytes (egg->buf, (const ut8 *)out, outlen);
	r_buf_prepend_bytes (egg->buf, (const ut8 *)".hex ", 5);
	free (out);
	return true;
}

static bool r_egg_prepend_bytes(REgg *egg, const ut8 *b, int len) {
	R_RETURN_VAL_IF_FAIL (egg && b, false);
	if (!r_egg_raw_prepend (egg, b, len)) {
		return false;
	}
	if (!r_buf_prepend_bytes (egg->bin, b, len)) {
		return false;
	}
	return true;
}

static bool r_egg_append_bytes(REgg *egg, const ut8 *b, int len) {
	R_RETURN_VAL_IF_FAIL (egg && b, false);
	if (!r_egg_raw (egg, b, len)) {
		return false;
	}
	if (!r_buf_append_bytes (egg->bin, b, len)) {
		return false;
	}
	return true;
}

// r_egg_block (egg, FRAME | IF | ELSE | ENDIF | FOR | WHILE, sz)
R_API void r_egg_if(REgg *egg, const char *reg, char cmp, int v) {
	//	egg->depth++;
}

R_API void r_egg_printf(REgg *egg, const char *fmt, ...) {
	R_RETURN_IF_FAIL (egg && fmt);
	va_list ap;
	int len;
	char buf[1024];
	va_start (ap, fmt);
	len = vsnprintf (buf, sizeof (buf), fmt, ap);
	R_LOG_DEBUG ("egg.printf %s", buf);
	r_buf_append_bytes (egg->buf, (const ut8 *)buf, len);
	va_end (ap);
}

R_API bool r_egg_assemble_asm(REgg *egg, char **asm_list) {
	char *asm_name = NULL;
	if (asm_list) {
		char **asm_ = asm_list;
		for (; *asm_; asm_ += 2) {
			if (!strcmp (egg->remit->arch, asm_[0])) {
				asm_name = asm_[1];
				break;
			}
		}
	}
	if (!asm_name) {
		if (egg->remit == &emit_x86 || egg->remit == &emit_x64) {
			asm_name = "x86.nz";
		} else if (egg->remit == &emit_a64 || egg->remit == &emit_arm) {
			asm_name = "arm";
		}
	}
	bool ret = false;
	if (asm_name) {
		r_asm_use (egg->rasm, asm_name);
		r_asm_use_assembler (egg->rasm, asm_name);
		r_asm_set_bits (egg->rasm, egg->bits);
		r_asm_set_big_endian (egg->rasm, egg->endian);
		// r_asm_set_syntax (egg->rasm, R_ARCH_SYNTAX_INTEL);
		r_arch_config_set_syntax (egg->rasm->config, R_ARCH_SYNTAX_INTEL);
		char *code = r_buf_tostring (egg->buf);
		if (R_STR_ISEMPTY (code)) {
			if (r_buf_size (egg->bin) == 0) {
				R_LOG_DEBUG ("The egg compiler generated no code to assemble");
				ret = true;
			} else {
				ret = true;
			}
		} else {
			RAsmCode *asmcode = r_asm_assemble (egg->rasm, code);
			if (asmcode && asmcode->len > 0) {
				ret = true;
				r_buf_append_bytes (egg->bin, asmcode->bytes, asmcode->len);
			} else {
				R_LOG_ERROR ("r_asm_massemble has failed %s", code);
			}
			r_asm_code_free (asmcode);
			free (code);
		}
	} else {
		R_LOG_ERROR ("Cannot find a valid assembler");
	}
	return ret;
}

R_API bool r_egg_assemble(REgg *egg) {
	return r_egg_assemble_asm (egg, NULL);
}

R_API bool r_egg_compile(REgg *egg) {
	R_RETURN_VAL_IF_FAIL (egg, false);
	r_buf_seek (egg->src, 0, R_BUF_SET);
	char b;
	int r = r_buf_read (egg->src, (ut8 *)&b, sizeof (b));
	if (r != sizeof (b) || !egg->remit) {
		return true;
	}
	// only emit begin if code is found
	r_egg_lang_init (egg);
	for (; b;) {
		r_egg_lang_parsechar (egg, b);
		if (egg->lang.elem_n >= sizeof (egg->lang.elem)) {
			R_LOG_ERROR ("too large element");
			break;
		}
		size_t r = r_buf_read (egg->src, (ut8 *)&b, sizeof (b));
		if (r != sizeof (b)) {
			break;
		}
		// XXX: some parse fail errors are false positives : (
	}
	if (egg->context > 0) {
		R_LOG_ERROR ("expected '}' at the end of the file. %d left", egg->context);
		return false;
	}
	return true;
}

R_API RBuffer *r_egg_get_bin(REgg *egg) {
	// TODO increment reference
	return egg->bin;
}

// R_API int r_egg_dump (REgg *egg, const char *file) { }

R_API char *r_egg_get_source(REgg *egg) {
	return r_buf_tostring (egg->src);
}

R_API char *r_egg_get_assembly(REgg *egg) {
	return r_buf_tostring (egg->buf);
}

R_API void r_egg_append(REgg *egg, const char *src) {
	r_buf_append_bytes (egg->src, (const ut8 *)src, strlen (src));
}

/* JIT : TODO: accept arguments here */
R_API int r_egg_run(REgg *egg) {
	R_RETURN_VAL_IF_FAIL (egg, -1);
	ut64 tmpsz;
	const ut8 *tmp = r_buf_data (egg->bin, &tmpsz);
	return r_sys_run (tmp, tmpsz);
}

R_API int r_egg_run_rop(REgg *egg) {
	ut64 sz;
	const ut8 *tmp = r_buf_data (egg->bin, &sz);
	return r_sys_run_rop (tmp, sz);
}

#define R_EGG_FILL_TYPE_TRAP
#define R_EGG_FILL_TYPE_NOP
#define R_EGG_FILL_TYPE_CHAR
#define R_EGG_FILL_TYPE_SEQ
#define R_EGG_FILL_TYPE_SEQ

static inline char *eon(char *n) {
	while (*n && (*n >= '0' && *n <= '9')) {
		n++;
	}
	return n;
}

/* padding looks like:
([snatSNAT][0-9]+)*
 */
R_API bool r_egg_padding(REgg *egg, const char *pad) {
	int number;
	ut8 *buf, padding_byte;
	char *p, *o = strdup (pad);

	for (p = o; *p;) { // parse pad string
		const char f = *p++;
		number = strtol (p, NULL, 10);

		if (number < 1) {
			R_LOG_ERROR ("Invalid padding length at %d", number);
			free (o);
			return false;
		}
		p = eon (p);

		switch (f) {
		case 's':
		case 'S': padding_byte = 0; break;
		case 'n':
		case 'N': padding_byte = 0x90; break;
		case 'a':
		case 'A': padding_byte = 'A'; break;
		case 't':
		case 'T': padding_byte = 0xcc; break;
		default:
			R_LOG_ERROR ("Invalid padding format (%c)", *p);
			eprintf ("Valid ones are:\n");
			eprintf ("	s S : NULL byte\n");
			eprintf ("	n N : nop\n");
			eprintf ("	a A : 0x41\n");
			eprintf ("	t T : trap (0xcc)\n");
			free (o);
			return false;
		}

		buf = malloc (number);
		if (!buf) {
			free (o);
			return false;
		}

		memset (buf, padding_byte, number);
		if (f >= 'a' && f <= 'z') {
			r_egg_prepend_bytes (egg, buf, number);
		} else {
			r_egg_append_bytes (egg, buf, number);
		}
		free (buf);
	}
	free (o);
	return true;
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

R_API bool r_egg_shellcode(REgg *egg, const char *name) {
	R_RETURN_VAL_IF_FAIL (egg && name, false);
	REggPlugin *p;
	RListIter *iter;
	RBuffer *b;
	r_list_foreach (egg->plugins, iter, p) {
		const char *p_name = p->meta.name;
		if (p->type == R_EGG_PLUGIN_SHELLCODE && !strcmp (name, p_name)) {
			b = p->build (egg);
			if (!b) {
				R_LOG_ERROR ("%s Shellcode has failed", p_name);
				return false;
			}
			ut64 tmpsz;
			const ut8 *tmp = r_buf_data (b, &tmpsz);
			r_egg_raw (egg, tmp, tmpsz);
			return true;
		}
	}
	return false;
}

R_API bool r_egg_encode(REgg *egg, const char *name) {
	REggPlugin *p;
	RListIter *iter;
	r_list_foreach (egg->plugins, iter, p) {
		if (p->type == R_EGG_PLUGIN_ENCODER && !strcmp (name, p->meta.name)) {
			RBuffer *b = p->build (egg);
			if (b) {
				r_buf_free (egg->bin);
				egg->bin = b;
				return true;
			}
			return false;
		}
	}
	return false;
}

R_API bool r_egg_patch(REgg *egg, int off, const ut8 *buf, int len) {
	struct egg_patch_t *ep = R_NEW (struct egg_patch_t);
	if (!ep) {
		return false;
	}
	ep->b = r_buf_new_with_bytes (buf, len);
	if (!ep->b) {
		egg_patch_free (ep);
		return false;
	}
	ep->off = off;
	r_list_append (egg->patches, ep);
	return true;
}

R_API void r_egg_finalize(REgg *egg) {
	struct egg_patch_t *ep;
	RListIter *iter;
	if (!egg->bin) {
		r_buf_free (egg->bin);
		egg->bin = r_buf_new ();
	}
	r_list_foreach (egg->patches, iter, ep) {
		if (ep->off < 0) {
			ut64 sz;
			const ut8 *buf = r_buf_data (ep->b, &sz);
			r_egg_append_bytes (egg, buf, sz);
		} else if (ep->off < r_buf_size (egg->bin)) {
			ut64 sz;
			const ut8 *buf = r_buf_data (ep->b, &sz);
			int r = r_buf_write_at (egg->bin, ep->off, buf, sz);
			if (r < sz) {
				R_LOG_ERROR ("cannot write");
				return;
			}
		} else {
			R_LOG_ERROR ("Cannot patch outside");
			return;
		}
	}
}

R_API void r_egg_pattern(REgg *egg, int size) {
	char *ret = r_debruijn_pattern ((int)size, 0, NULL);
	if (ret) {
		r_egg_prepend_bytes (egg, (const ut8 *)ret, strlen (ret));
		free (ret);
	} else {
		R_LOG_ERROR ("Invalid debruijn pattern length");
	}
}
