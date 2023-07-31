/* radare - LGPL - Copyright 2009-2023 - pancake, nibble */

// needed for spp
#define USE_R2 1
#include <r_core.h>
#include <spp/spp.h>
#include <config.h>

R_LIB_VERSION (r_asm);

static const char *directives[] = {
	".include", ".error", ".warning",
	".echo", ".if", ".ifeq", ".endif",
	".else", ".set", ".get", ".extern", NULL
};

/* pseudo.c - private api */
static int r_asm_pseudo_align(RAsmCode *acode, RAnalOp *op, const char *input) {
	acode->code_align = r_num_math (NULL, input);
	return 0;
}

static int r_asm_pseudo_string(RAnalOp *op, char *input, int zero) {
	int len = strlen (input) - 1;
	if (len < 1) {
		return 0;
	}
	// TODO: if not starting with '"'.. give up
	if (input[len] == '"') {
		input[len] = 0;
	}
	if (*input == '"') {
		input++;
	}
	len = r_str_unescape (input) + zero;
	r_anal_op_set_mnemonic (op, op->addr, input);
	r_anal_op_set_bytes (op, op->addr, (const ut8*)input, len + 1);
	return len;
}

static inline int r_asm_pseudo_bits(RAsm *a, const char *input) {
	if (!(r_asm_set_bits (a, r_num_math (NULL, input)))) {
		R_LOG_ERROR ("Unsupported value for .bits");
		return -1;
	}
	return 0;
}

static inline bool r_asm_pseudo_org(RAsm *a, const char *input) {
	r_asm_set_pc (a, r_num_math (NULL, input));
	return true;
}

static inline int r_asm_pseudo_intN(RAsm *a, RAnalOp *op, char *input, int n) {
	short s;
	int i;
	long int l;
	ut64 s64 = r_num_math (NULL, input);
	if (n != 8 && s64 >> (n * 8)) {
		R_LOG_ERROR ("int%d Out is out of range", n);
		return 0;
	}
	ut8 *buf = malloc (8);
	if (!buf) {
		return 0;
	}
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	if (n == 2) {
		s = (short)s64;
		r_write_ble16 (buf, s, be);
	} else if (n == 4) {
		i = (int)s64;
		r_write_ble32 (buf, i, be);
	} else if (n == 8) {
		l = (long int)s64;
		r_write_ble64 (buf, l, be);
	} else {
		free (buf);
		return 0;
	}
	free (op->bytes);
	op->bytes = buf;
	op->size = n;
	return n;
}

static inline int r_asm_pseudo_int16(RAsm *a, RAnalOp *op, char *input) {
	return r_asm_pseudo_intN (a, op, input, 2);
}

static inline int r_asm_pseudo_int32(RAsm *a, RAnalOp *op, char *input) {
	return r_asm_pseudo_intN (a, op, input, 4);
}

static inline int r_asm_pseudo_int64(RAsm *a, RAnalOp *op, char *input) {
	return r_asm_pseudo_intN (a, op, input, 8);
}

static inline int r_asm_pseudo_byte(RAnalOp *op, char *input) {
	int i, len = 0;
	r_str_replace_char (input, ',', ' ');
	len = r_str_word_count (input);
	r_str_word_set0 (input);
	ut8 *buf = malloc (len);
	if (!buf) {
		return 0;
	}
	for (i = 0; i < len; i++) {
		const char *word = r_str_word_get0 (input, i);
		int num = (int)r_num_math (NULL, word);
		buf[i] = num;
	}
	r_asm_op_set_buf (op, buf, len);
	free (buf);
	return len;
}

static inline int r_asm_pseudo_fill(RAnalOp *op, const char *input) {
	int i, repeat = 0, size = 0, value = 0;
	if (strchr (input, ',')) {
		int res = sscanf (input, "%d,%d,%d", &repeat, &size, &value); // use r_num?
		if (res != 3) {
			R_LOG_ERROR ("Invalid usage of .fill repeat,size,value");
			R_LOG_ERROR ("for example: .fill 1,0x100,0");
			return -1;
		}
	} else {
		ut64 v = r_num_math (NULL, input);
		size = (int)v;
		repeat = 1;
	}
	size *= (sizeof (value) * repeat);
	if (size > 0) {
		ut8 *buf = malloc (size);
		if (buf) {
			for (i = 0; i < size; i += sizeof (value)) {
				memcpy (&buf[i], &value, sizeof (value));
			}
			r_asm_op_set_buf (op, buf, size);
			free (buf);
		}
	} else {
		size = 0;
	}
	return size;
}

static inline int r_asm_pseudo_incbin(RAnalOp *op, char *input) {
	size_t bytes_read = 0;
	r_str_replace_char (input, ',', ' ');
	// int len = r_str_word_count (input);
	r_str_word_set0 (input);
	//const char *filename = r_str_word_get0 (input, 0);
	size_t skip = (size_t)r_num_math (NULL, r_str_word_get0 (input, 1));
	size_t count = (size_t)r_num_math (NULL,r_str_word_get0 (input, 2));
	char *content = r_file_slurp (input, &bytes_read);
	if (!content) {
		R_LOG_ERROR ("Could not open '%s'", input);
		return -1;
	}
	if (skip > 0) {
		skip = skip > bytes_read ? bytes_read : skip;
	}
	if (count > 0) {
		count = count > bytes_read ? 0 : count;
	} else {
		count = bytes_read;
	}
#if 0
	// Need to handle arbitrary amount of data
	r_buf_free (op->buf_inc);
	op->buf_inc = r_buf_new_with_string (content + skip);
#endif
	// Terminate the original buffer
	free (content);
	return count;
}

R_API RAsm *r_asm_new(void) {
	RAsm *a = R_NEW0 (RAsm);
	if (!a) {
		return NULL;
	}
	a->codealign = 1;
	a->dataalign = 1;
	a->plugins = r_list_newf (NULL);
	if (!a->plugins) {
		free (a);
		return NULL;
	}
	a->config = r_arch_config_new ();
	a->parse = r_parse_new ();
	return a;
}

// TODO must use the internal rparse api when both libraries are merged
R_API bool r_asm_sub_names_input(RAsm *a, const char *f) {
	r_return_val_if_fail (a && f, false);
	if (!a->ifilter) {
		a->ifilter = r_parse_new ();
	}
	if (!r_parse_use (a->ifilter, f)) {
		r_parse_free (a->ifilter);
		a->ifilter = NULL;
		return false;
	}
	return true;
}

// TODO must use the internal rparse api when both libraries are merged
R_API bool r_asm_sub_names_output(RAsm *a, const char *f) {
	r_return_val_if_fail (a && f, false);
	if (!a->ofilter) {
		a->ofilter = r_parse_new ();
	}
	if (!r_parse_use (a->ofilter, f)) {
		r_parse_free (a->ofilter);
		a->ofilter = NULL;
		return false;
	}
	return true;
}

R_API void r_asm_free(RAsm *a) {
	if (!a) {
		return;
	}
	// r_unref (a->config);
	if (a->plugins) {
		r_list_free (a->plugins);
		a->plugins = NULL;
	}
	r_parse_free (a->parse);
	r_unref (a->config);
	r_syscall_free (a->syscall);
	sdb_free (a->pair);
	ht_pp_free (a->flags);
	a->pair = NULL;
	free (a);
}

R_API void r_asm_set_user_ptr(RAsm *a, void *user) {
	a->user = user;
}

R_API bool r_asm_use_assembler(RAsm *a, const char *name) {
	r_return_val_if_fail (a && name, false);
	// TODO not implemented
	return false;
}

static void load_asm_descriptions(RAsm *a) {
	const char *arch = a->config->arch;
	if (!arch || !strcmp (arch, "any")) {
		arch = a->config->cpu;
	}
	if (!arch) {
		return;
	}
#if HAVE_GPERF
	SdbGperf *gp = r_asm_get_gperf (arch);
	if (gp) {
		sdb_free (a->pair);
		a->pair = sdb_new0 ();
		sdb_open_gperf (a->pair, gp);
		return;
	}
#endif
	char *r2prefix = r_str_r2_prefix (R2_SDB_OPCODES);
	char *file = r_str_newf ("%s/%s.sdb", r_str_getf (r2prefix), arch);
	if (file) {
#if 0
		sdb_reset (a->pair);
#else
		sdb_free (a->pair);
		a->pair = sdb_new (NULL, file, 0);
#endif
		free (file);
	}
	free (r2prefix);
}

R_API bool r_asm_use(RAsm *a, const char *name) {
	r_return_val_if_fail (a, false);
	if (R_STR_ISEMPTY (name)) {
		// that shouldnt be permitted imho, keep for backward compat
		return false;
	}
	r_arch_config_use (a->config, name);
	r_asm_use_assembler (a, name);
	char *dotname = strdup (name);
	char *vv = strchr (dotname, '.');
	if (vv) {
		*vv = 0;
	} else {
		R_FREE (dotname);
	}
	if (a->analb.anal) {
		if (a->analb.use (a->analb.anal, name)) {
			load_asm_descriptions (a);
			// a->cur = NULL;
			// a->acur = NULL;
			return true;
		}
		R_LOG_ERROR ("Cannot find '%s' asm/arch/anal plugin. See rasm2 -L or -LL", name);
	}
	if (strcmp (name, "null")) {
		return r_asm_use (a, "null");
	}
	return false;
}

// XXX this is r_arch
R_DEPRECATE R_API void r_asm_set_cpu(RAsm *a, const char *cpu) {
	r_return_if_fail (a);
	r_arch_config_set_cpu (a->config, cpu);
}

R_DEPRECATE R_API int r_asm_set_bits(RAsm *a, int bits) {
	a->config->bits = bits;
	return true;
}

R_API bool r_asm_set_big_endian(RAsm *a, bool b) {
	r_return_val_if_fail (a, false);
#if 0
	if (a->cur) {
		switch (a->cur->endian) {
		case R_SYS_ENDIAN_NONE:
		case R_SYS_ENDIAN_BI:
			// TODO: not yet implemented
			a->config->big_endian = b ? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;
			break;
		case R_SYS_ENDIAN_LITTLE:
			a->config->big_endian = false;
			a->config->endian = R_SYS_ENDIAN_LITTLE;
			break;
		case R_SYS_ENDIAN_BIG:
			a->config->big_endian = true;
			a->config->endian = R_SYS_ENDIAN_BIG;
			break;
		default:
			R_LOG_WARN ("no endianness specified");
			break;
		}
	} else {
	}
#endif
	// default is host endian
	// a->config->endian = R_SYS_ENDIAN ? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE; // default is host endian
	if (a->arch) {
		r_arch_set_endian (a->arch, a->config->endian);
	}
	a->config->endian = b ? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;
	return R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
}

R_API int r_asm_set_pc(RAsm *a, ut64 pc) {
	a->pc = pc;
	return true;
}

static bool is_invalid(RAnalOp *op) {
	const char *text = op->mnemonic;
	return (text && !strcmp (text, "invalid"));
}

R_API int r_asm_disassemble(RAsm *a, RAnalOp *op, const ut8 *buf, int len) {
	r_asm_op_init (op);
	r_return_val_if_fail (a && buf && op, -1);
	if (len < 1) {
		return 0;
	}

	int ret = 0; // op->payload = 0;
	op->size = 4;
	// op->bitsize = 0;
	r_anal_op_set_mnemonic (op, op->addr, "");
	if (a->config->codealign) {
		const int mod = a->pc % a->config->codealign;
		if (mod) {
			r_anal_op_set_mnemonic (op, op->addr, "unaligned");
			op->size = a->config->codealign - mod;
			return -1;
		}
	}
	if (a->analb.anal) {
		// disassemble using the analysis plugin if found
		// a->analb.opinit (op);
		ret = a->analb.decode (a->analb.anal, op, a->pc, buf, len, R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_DISASM);
		// r_strbuf_set (&op->buf_asm, aop.mnemonic? aop.mnemonic: "");
		// a->analb.opfini (op);
	}
	if (ret < 0) {
		ret = 0;
	}
#if 0
	if (op->bitsize > 0) {
		op->size = op->bitsize / 8;
		a->config->bitshift += op->bitsize % 8;
		int count = a->config->bitshift / 8;
		if (count > 0) {
			op->size = op->size + count;
			a->config->bitshift %= 8;
		}
	}
#endif
	if (op->size < 1 || is_invalid (op)) {
		if (a->config->invhex) {
			r_strf_buffer (32);
			if (a->config->bits == 16) {
				ut16 b = r_read_le16 (buf);
				r_anal_op_set_mnemonic (op, op->addr, r_strf (".word 0x%04x", b));
			} else {
				ut32 b = r_read_le32 (buf);
				r_anal_op_set_mnemonic (op, op->addr, r_strf (".dword 0x%08x", b));
			}
			// TODO: something for 64bits too?
		} else {
			r_anal_op_set_mnemonic (op, op->addr, "invalid");
		}
	}
	if (a->ofilter) {
		char *newtext = r_parse_instruction (a->ofilter, op->mnemonic);
		if (newtext) {
			r_anal_op_set_mnemonic (op, op->addr, newtext);
		}
	}
	int opsz = (op->size > 0)? R_MAX (0, R_MIN (len, op->size)): 1;
	r_anal_op_set_bytes (op, op->addr, buf, opsz);
	return ret;
}

typedef int (*Ase)(RAsm *a, RAnalOp *op, const char *buf);

static char *replace_directives_for(char *str, const char *token) {
	RStrBuf *sb = r_strbuf_new ("");
	char *p = NULL;
	char *q = str;
	bool changes = false;
	for (;;) {
		if (q) {
			p = strstr (q, token);
		}
		if (p) {
			char *nl = strchr (p, '\n');
			if (nl) {
				*nl++ = 0;
			}
			char _ = *p;
			*p = 0;
			r_strbuf_append (sb, q);
			*p = _;
			r_strbuf_appendf (sb, "<{%s}>\n", p + 1);
			q = nl;
			changes = true;
		} else {
			if (q) {
				r_strbuf_append (sb, q);
			}
			break;
		}
	}
	if (changes) {
		free (str);
		return r_strbuf_drain (sb);
	}
	r_strbuf_free (sb);
	return str;
}

static char *replace_directives(char *str) {
	int i = 0;
	const char *dir = directives[i++];
	char *o = replace_directives_for (str, dir);
	while (dir) {
		o = replace_directives_for (o, dir);
		dir = directives[i++];
	}
	return o;
}

R_API void r_asm_list_directives(void) {
	int i = 0;
	const char *dir = directives[i++];
	while (dir) {
		printf ("%s\n", dir);
		dir = directives[i++];
	}
}

// returns instruction size
static int r_asm_assemble(RAsm *a, RAnalOp *op, const char *buf) {
	r_return_val_if_fail (a && op && buf, 0);
	int ret = 0;
	char *b = strdup (buf);
	if (!b) {
		return 0;
	}
	if (a->ifilter) {
		r_parse_parse (a->ifilter, buf, b);
	}
	r_str_case (b, false); // to-lower
	if (a->analb.anal) {
		ut8 buf[256] = {0};
		a->analb.anal->arch->cfg->endian = a->config->endian;
		// XXX we should use just RArch and ecur/dcur
		ret = a->analb.encode (a->analb.anal, a->pc, b, buf, sizeof (buf));
		if (ret > 0) {
			r_anal_op_set_bytes (op, a->pc, buf, R_MIN (ret, sizeof (buf)));
		}
#if 0
	} else if (ase) {
		/* find callback if no assembler support in current plugin */
		ret = ase (a, op, b);
#endif
	}
	free (b);
	return ret;
}

R_API RAsmCode* r_asm_mdisassemble(RAsm *a, const ut8 *buf, int len) {
	r_return_val_if_fail (a && buf && len >= 0, NULL);

	ut64 pc = a->pc;
	ut64 idx;
	int ret;
	// XXX move from io to archconfig!! and remove the dependency on core!
	const size_t addrbytes = a->user? ((RCore *)a->user)->io->addrbytes: 1;
	int mininstrsize = 1; // TODO: use r_arch_info();

	RAsmCode *acode = r_asm_code_new ();
	if (!acode) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new (NULL);
	acode->bytes = r_mem_dup (buf, len);

	for (idx = 0; idx + addrbytes <= len; idx += (addrbytes * ret)) {
		RAnalOp op = {0};
		r_anal_op_init (&op);
		r_asm_set_pc (a, pc + idx);
		/// we can change this to return RAnalOp* instead of passing it as arg here
		ret = r_asm_disassemble (a, &op, buf + idx, len - idx);
		if (ret < 1) {
			ret = mininstrsize;
		}
		ret = op.size;
		if (a->ofilter) {
			char *newtext = r_parse_instruction (a->ofilter, op.mnemonic);
			if (newtext) {
				free (op.mnemonic);
				op.mnemonic = newtext;
			}
		}
		if (op.mnemonic) {
			r_strbuf_append (sb, op.mnemonic);
			r_strbuf_append (sb, "\n");
		}
		r_anal_op_fini (&op);
	}
	acode->assembly = r_strbuf_drain (sb);
	acode->len = idx;
	return acode;
}

R_API RAsmCode* r_asm_mdisassemble_hexstr(RAsm *a, RParse *p, const char *hexstr) {
	ut8 *buf = malloc (strlen (hexstr) + 1);
	if (!buf) {
		return NULL;
	}
	int len = r_hex_str2bin (hexstr, buf);
	if (len < 1) {
		free (buf);
		return NULL;
	}
	RAsmCode *ret = r_asm_mdisassemble (a, buf, (ut64)len);
	if (ret && p) {
		// XXX this can crash the output buffer
		r_parse_parse (p, ret->assembly, ret->assembly);
	}
	free (buf);
	return ret;
}

static void __flag_free_kv(HtPPKv *kv) {
	if (kv) {
		free (kv->key);
		free (kv->value);
	// 	free (kv); // causes double free
	}
}

static void *__dup_val(const void *v) {
	return (void *)strdup ((char *)v);
}

static int parse_asm_directive(RAsm *a, RAnalOp *op, RAsmCode *acode, char *ptr_start, R_INOUT ut64 *off) {
	const char *asmcpu = R_UNWRAP3 (a, config, cpu);
	int ret = -1;
	char *ptr = ptr_start;
	char *ptr2 = NULL;
	r_str_trim (ptr);
	if (r_str_startswith (ptr, ".intel_syntax")) {
		a->config->syntax = R_ARCH_SYNTAX_INTEL;
	} else if (r_str_startswith (ptr, ".att_syntax")) {
		a->config->syntax = R_ARCH_SYNTAX_ATT;
	} else if (r_str_startswith (ptr, ".endian")) {
		r_asm_set_big_endian (a, atoi (ptr + 7));
	} else if (r_str_startswith (ptr, ".big_endian")) {
		r_asm_set_big_endian (a, true);
	} else if (r_str_startswith (ptr, ".lil_endian") || r_str_startswith (ptr, "little_endian")) {
		r_asm_set_big_endian (a, false);
	} else if (r_str_startswith (ptr, ".asciz")) {
		char *str = r_str_trim_dup (ptr + 6);
		ret = r_asm_pseudo_string (op, ptr + 6, 1);
		free (str);
	} else if (r_str_startswith (ptr, ".extern")) {
		char *str = r_str_trim_dup (ptr + strlen (".extern"));
		if (!r_asm_code_equ_get (acode, str)) {
			void *p = r_lib_dl_open ("libr_core."R_LIB_EXT);
			void *a = r_lib_dl_sym (p, str);
			if (a) {
				char *val = r_str_newf ("%p", a);
				// Will be good to have a separate api for R2_590 to let the caller resolve those pointers
				r_asm_code_set_equ (acode, str, val);
				R_LOG_INFO ("Resolved symbol '%s' = %s", str, val);
				free (val);
			} else {
				R_LOG_WARN ("Cannot resolve '%s'", str);
			}
			free (str);
			r_lib_dl_close (p);
		}
		ret = 0;
	} else if (r_str_startswith (ptr, ".string ")) {
		char *str = r_str_trim_dup (ptr + 8);
		ret = r_asm_pseudo_string (op, str, 1);
		free (str);
	} else if (r_str_startswith (ptr, ".ascii")) {
		char *str = r_str_trim_dup (ptr + 6);
		ret = r_asm_pseudo_string (op, ptr + 6, 1);
		free (str);
	} else if (r_str_startswith (ptr, ".align")) {
		char *str = r_str_trim_dup (ptr + 6);
		ret = r_asm_pseudo_align (acode, op, str);
		free (str);
	} else if (r_str_startswith (ptr, ".arm64")) {
		r_asm_use (a, "arm");
		r_asm_set_bits (a, 64);
		ret = 0;
	} else if (r_str_startswith (ptr, ".arm")) {
		r_asm_use (a, "arm");
		r_asm_set_bits (a, 32);
		ret = 0;
	} else if (r_str_startswith (ptr, ".thumb")) {
		r_asm_use (a, "arm");
		r_asm_set_bits (a, 16);
		ret = 0;
	} else if (r_str_startswith (ptr, ".arch ")) {
		if (r_asm_use (a, ptr + 6)) {
			ret = 0;
		} else {
			R_LOG_ERROR ("cannot use %s", ptr + 6);
		}
	} else if (r_str_startswith (ptr, ".bits ")) {
		ret = r_asm_pseudo_bits (a, ptr + 6);
	} else if (r_str_startswith (ptr, ".fill ")) {
		ret = r_asm_pseudo_fill (op, ptr + 6);
	} else if (r_str_startswith (ptr, ".kernel ")) {
		r_syscall_setup (a->syscall, a->config->arch, a->config->bits, asmcpu, ptr + 8);
	} else if (r_str_startswith (ptr, ".cpu ")) {
		r_asm_set_cpu (a, ptr + 5);
	} else if (r_str_startswith (ptr, ".os ")) {
		r_syscall_setup (a->syscall, a->config->arch, a->config->bits, asmcpu, ptr + 4);
	} else if (r_str_startswith (ptr, ".hex ")) {
		ret = r_asm_op_set_hex (op, ptr + 5);
	} else if ((r_str_startswith (ptr, ".int16 ")) || r_str_startswith (ptr, ".short ")) {
		ret = r_asm_pseudo_int16 (a, op, ptr + 7);
	} else if (r_str_startswith (ptr, ".int32 ")) {
		ret = r_asm_pseudo_int32 (a, op, ptr + 7);
	} else if (r_str_startswith (ptr, ".int64 ")) {
		char *str = r_asm_code_equ_replace (acode, strdup (ptr + 7));
		ret = r_asm_pseudo_int64 (a, op, str); // ptr + 7);
		free (str);
	} else if (r_str_startswith (ptr, ".size")) {
		ret = 0; // do nothing, ignored
	} else if (r_str_startswith (ptr, ".section")) {
		ret = 0; // do nothing, ignored
	} else if (r_str_startswith (ptr, ".byte ") || r_str_startswith (ptr, ".int8 ")) {
		ret = r_asm_pseudo_byte (op, ptr + 6);
	} else if (r_str_startswith (ptr, ".glob")) {
		// .global .globl
		R_LOG_DEBUG (".global directive does nothing for now");
		ret = 0;
	} else if (r_str_startswith (ptr, ".equ ")) {
		ptr2 = strchr (ptr + 5, ',');
		if (!ptr2) {
			ptr2 = strchr (ptr + 5, '=');
		}
		if (!ptr2) {
			ptr2 = strchr (ptr + 5, ' ');
		}
		if (ptr2) {
			*ptr2 = '\0';
			r_asm_code_set_equ (acode, ptr + 5, ptr2 + 1);
			ret = 0;
		} else {
			R_LOG_ERROR ("Invalid syntax for '.equ': Use '.equ <word> <word>'");
		}
	} else if (r_str_startswith (ptr, ".org ")) {
		if (r_asm_pseudo_org (a, ptr + 5)) {
			ret = 0;
			*off = a->pc;
		}
	} else if (r_str_startswith (ptr, ".offset ")) {
		R_LOG_ERROR ("Invalid use of the .offset directory. This directive is only supported in r2 -c 'waf'");
	} else if (r_str_startswith (ptr, ".text")) {
		acode->code_offset = a->pc;
		ret = 0;
	} else if (r_str_startswith (ptr, ".data")) {
		acode->data_offset = a->pc;
		ret = 0;
	} else if (r_str_startswith (ptr, ".incbin")) {
		if (ptr[7] != ' ') {
			R_LOG_ERROR ("incbin missing filename");
			return 0;
		}
		ret = r_asm_pseudo_incbin (op, ptr + 8);
	} else {
		R_LOG_ERROR ("Unknown directive (%s)", ptr);
		return -1;
	}
	// ret =  0 -> cause the parent the continue
	// ret = -1 -> error, parent must goto fail
	// ret = >0 -> success, move on
	return ret;
}

static inline char *next_token(const char *tok) {
	const char *const delimiters = ";\n\r";
	const char *d = delimiters;
	for (; *d; d++) {
		char *ptr = strchr (tok, *d);
		if (ptr) {
			return ptr;
		}
	}
	return NULL;
}

R_API RAsmCode *r_asm_massemble(RAsm *a, const char *assembly) {
	int num, stage, ret, idx, ctr, i, linenum = 0;
	char *lbuf = NULL, *ptr = NULL, *ptr_start = NULL;
	RAsmCode *acode = NULL;
	RAnalOp op = {0};
	ut64 off, pc;

	char *buf_token = NULL;
	size_t tokens_size = 32;
	char **tokens = calloc (sizeof (char*), tokens_size);
	if (!tokens) {
		return NULL;
	}
	if (!assembly) {
		free (tokens);
		return NULL;
	}
	ht_pp_free (a->flags);
	if (!(a->flags = ht_pp_new (__dup_val, __flag_free_kv, NULL))) {
		free (tokens);
		return NULL;
	}
	if (!(acode = r_asm_code_new ())) {
		free (tokens);
		return NULL;
	}
	acode->assembly = strdup (assembly);
	acode->bytes = calloc (1, 64);
	lbuf = strdup (assembly);
	acode->code_align = 0;

	/* consider ,, an alias for a newline */
	lbuf = r_str_replace (lbuf, ",,", "\n", true);
	/* accept ';' as comments when input is multiline */
	{
		char *nl = strchr (lbuf, '\n');
		if (nl) {
			if (strchr (nl + 1, '\n')) {
				r_str_replace_char (lbuf, ';', '#');
			}
		}
	}
	// XXX: ops like mov eax, $pc+33 fail coz '+' is not a valid number!!!
	// XXX: must be handled here to be global.. and not arch-specific
	{
		char val[32];
		snprintf (val, sizeof (val), "0x%"PFMT64x, a->pc);
		lbuf = r_str_replace (lbuf, "$$", val, 1);
	}
	if (a->syscall) {
		char val[32];
		char *aa, *p = strstr (lbuf, "$sys.");
		while (p) {
			char *sp = (char*)r_str_closer_chr (p, " \n\r#");
			if (sp) {
				char osp = *sp;
				*sp = 0;
				aa = strdup (p);
				*sp = osp;
				num = r_syscall_get_num (a->syscall, aa+5);
				snprintf (val, sizeof (val), "%d", num);
				lbuf = r_str_replace (lbuf, aa, val, 1);
				free (aa);
			}
			p = strstr (p + 5, "$sys.");
		}
	}
	bool labels = !!strchr (lbuf, ':');

	/* Tokenize */
	for (tokens[0] = lbuf, ctr = 0; (ptr = next_token (tokens[ctr])); ) {
		if (ctr + 1 >= tokens_size) {
			const size_t new_tokens_size = tokens_size * 2;
			if (sizeof (char*) * new_tokens_size <= sizeof (char*) * tokens_size) {
				// overflow
				R_LOG_ERROR ("Too many tokens");
				goto fail;
			}
			char **new_tokens = realloc (tokens, sizeof (char*) * new_tokens_size);
			if (!new_tokens) {
				R_LOG_ERROR ("Too many tokens");
				goto fail;
			}
			tokens_size = new_tokens_size;
			tokens = new_tokens;
		}
		ctr++;
		*ptr = '\0';
		tokens[ctr] = ptr + 1;
	}

#define isavrseparator(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r'|| (x) == ' '|| \
		(x) == ',' || (x) == ';' || (x) == '[' || (x) == ']'|| \
		(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')

	/* Stage 0-2: Parse labels*/
	/* Stage 3: Assemble */
// XXX: stages must be dynamic. until all equs have been resolved
#define STAGES 5
	pc = a->pc;
	bool inComment = false;
	for (stage = 0; stage < STAGES; stage++) {
		if (stage < 2 && !labels) {
			continue;
		}
		inComment = false;
		r_asm_set_pc (a, pc);
		for (idx = ret = i = 0, off = a->pc; i <= ctr; i++, idx += ret) {
			buf_token = tokens[i];
			if (!buf_token) {
				continue;
			}
			if (inComment) {
				if (r_str_startswith (ptr_start, "*/")) {
					inComment = false;
				}
				continue;
			}
			// XXX TODO remove arch-specific hacks
			const char *cur_arch = R_UNWRAP3 (a, config, arch);
			if (cur_arch && r_str_startswith (cur_arch, "avr")) {
				for (ptr_start = buf_token; *ptr_start && isavrseparator (*ptr_start); ptr_start++);
			} else {
				for (ptr_start = buf_token; *ptr_start && IS_SEPARATOR (*ptr_start); ptr_start++);
			}
			if (r_str_startswith (ptr_start, "/*")) {
				if (!strstr (ptr_start + 2, "*/")) {
					inComment = true;
				}
				continue;
			}
			/* Comments */
			{
				bool likely_comment = true;
				char* cptr = strchr (ptr_start, ',');
				ptr = strchr (ptr_start, '#');
				// a comma is probably not followed by a comment
				// 8051 often uses #symbol notation as 2nd arg
				if (cptr && ptr && cptr < ptr) {
					likely_comment = false;
					for (cptr += 1; cptr < ptr ; cptr += 1) {
						if (! isspace ((int) *cptr)) {
							likely_comment = true;
							break;
						}
					}
				}
				// # followed by number literal also
				// isn't likely to be a comment
				likely_comment = likely_comment && ptr
					&& !R_BETWEEN ('0', ptr[1], '9')
					&& ptr[1] != '-' ;
				if (likely_comment) {
					*ptr = '\0';
				}
			}
			r_asm_set_pc (a, a->pc + ret);
			off = a->pc;
			ret = 0;
			if (!*ptr_start) {
				continue;
			}
			linenum++;
			/* labels */
			if (labels && (ptr = strchr (ptr_start, ':'))) {
				bool is_a_label = true;
				char *q = ptr_start;
				while (*q) {
					if (*q == ' ') {
						is_a_label = false;
						break;
					}
					q++;
				}
				if (is_a_label) {
					//if (stage != 2) {
					if (ptr_start[1] && ptr_start[1] != ' ') {
						*ptr = 0;
						char *p = strdup (ptr_start);
						*ptr = ':';
						if (acode->code_align) {
							off += (acode->code_align - (off % acode->code_align));
						}
						char *food = r_str_newf ("0x%"PFMT64x, off);
						if (food) {
							ht_pp_insert (a->flags, ptr_start, food);
							r_asm_code_set_equ (acode, p, food);
							free (food);
						}
						free (p);
					}
					//}
					ptr_start = ptr + 1;
				}
				ptr = ptr_start;
			}
			if (!*ptr_start) {
				ret = 0;
				continue;
			}
			if (*ptr_start == '.') { /* pseudo */
				ret = parse_asm_directive (a, &op, acode, ptr_start, &off);
				if (ret < 0) {
					goto fail;
				} else if (ret == 0) {
					continue;
				}
			} else { /* Instruction */
				char *str = ptr_start;
				r_str_trim (str);
				if (a->ifilter) {
					r_parse_parse (a->ifilter, ptr_start, ptr_start);
				}
				if (acode->equs) {
					if (!*ptr_start) {
						continue;
					}
					str = r_asm_code_equ_replace (acode, strdup (ptr_start));
					ret = r_asm_assemble (a, &op, str);
					free (str);
				} else {
					if (!*ptr_start) {
						continue;
					}
					ret = r_asm_assemble (a, &op, ptr_start);
				}
			}
			if (stage == STAGES - 1) {
				if (ret < 1) {
					R_LOG_ERROR ("Cannot assemble '%s' at line %d", ptr_start, linenum);
					goto fail;
				}
				acode->len = idx + ret;
				char *newbuf = realloc (acode->bytes, (idx + ret) * 2);
				if (!newbuf) {
					goto fail;
				}
				acode->bytes = (ut8*)newbuf;
				if (op.size > 0) {
					memcpy (acode->bytes + idx, op.bytes, op.size);
				}
				memset (acode->bytes + idx + ret, 0, idx + ret);
#if 0
				if (op.buf_inc && r_buf_size (op.buf_inc) > 1) {
					char *inc = r_buf_tostring (op.buf_inc);
					r_buf_free (op.buf_inc);
					op.buf_inc = NULL;
					if (inc) {
						ret += r_hex_str2bin (inc, acode->bytes + idx + ret);
						free (inc);
					}
				}
#endif
			}
		}
	}
	free (lbuf);
	free (tokens);
	r_asm_op_fini (&op);
	return acode;
fail:
	free (lbuf);
	free (tokens);
	r_asm_op_fini (&op);
	r_asm_code_free (acode);
	return NULL;
}

#if 0
// XXX this is unused code!
R_API bool r_asm_modify(RAsm *a, ut8 *buf, int field, ut64 val) {
	return (a->cur && a->cur->modify) ? a->cur->modify (a, buf, field, val): false;
}
#endif

R_API char *r_asm_describe(RAsm *a, const char* str) {
	return (a && a->pair)? sdb_get (a->pair, str, 0): NULL;
}

R_API const RList* r_asm_get_plugins(RAsm *a) {
	return a->plugins;
}

/* to ease the use of the native bindings (not used in r2) */
R_API char *r_asm_tostring(RAsm *a, ut64 addr, const ut8 *b, int l) {
	r_return_val_if_fail (a && b && l >= 0, NULL);
	r_asm_set_pc (a, addr);
	RAsmCode *code = r_asm_mdisassemble (a, b, l);
	if (code) {
		char *buf_asm = code->assembly;
		code->assembly = NULL;
		r_asm_code_free (code);
		return buf_asm;
	}
	return NULL;
}

R_API ut8 *r_asm_from_string(RAsm *a, ut64 addr, const char *b, int *l) {
	r_asm_set_pc (a, addr);
	RAsmCode *code = r_asm_massemble (a, b);
	if (code) {
		ut8 *buf = code->bytes;
		if (l) {
			*l = code->len;
		}
		r_asm_code_free (code);
		return buf;
	}
	return NULL;
}

R_API int r_asm_syntax_from_string(const char *name) {
	r_return_val_if_fail (name, -1);
	if (!strcmp (name, "regnum")) {
		return R_ARCH_SYNTAX_REGNUM;
	}
	if (!strcmp (name, "jz")) {
		return R_ARCH_SYNTAX_JZ;
	}
	if (!strcmp (name, "intel")) {
		return R_ARCH_SYNTAX_INTEL;
	}
	if (!strcmp (name, "masm")) {
		return R_ARCH_SYNTAX_MASM;
	}
	if (!strcmp (name, "att")) {
		return R_ARCH_SYNTAX_ATT;
	}
	return -1;
}

R_API char *r_asm_mnemonics(RAsm *a, int id, bool json) {
	r_return_val_if_fail (a, NULL);
	// should use rarch instead!.. but for now ranal.mnemonics is calling arch.mnemonics..
	if (a->analb.anal && a->analb.mnemonics) {
		return a->analb.mnemonics (a->analb.anal, id, json);
	}
	return NULL;
}

R_API int r_asm_mnemonics_byname(RAsm *a, const char *name) {
	r_return_val_if_fail (a && name, 0);
	int i;
	for (i = 0; i < 9000; i++) {
		char *n = r_asm_mnemonics (a, i, false);
		if (n && !strcmp (n, name)) {
			return i;
		}
		free (n);
	}
	return 0;
}

R_API RAsmCode* r_asm_rasm_assemble(RAsm *a, const char *buf, bool use_spp) {
	r_return_val_if_fail (a && buf, NULL);
	char *lbuf = strdup (buf);
	if (!lbuf) {
		return NULL;
	}
	if (use_spp) {
		Output out;
		out.fout = NULL;
		out.cout = r_strbuf_new ("");
		r_strbuf_init (out.cout);
		struct Proc proc;
		spp_proc_set (&proc, "spp", 1);

		lbuf = replace_directives (lbuf);
		spp_eval (lbuf, &out);
		free (lbuf);
		lbuf = strdup (r_strbuf_get (out.cout));
	}
	RAsmCode *acode = r_asm_massemble (a, lbuf);
	free (lbuf);
	return acode;
}

R_API RList *r_asm_cpus(RAsm *a) {
	// R2_600 move to r_arch api instead?
	const char *cpus = R_UNWRAP5 (a, arch, session, plugin, cpus);
	RList *list = cpus
		? r_str_split_duplist (cpus, ",", 0)
		: r_list_newf (free);
	r_list_sort (list, (RListComparator)strcmp);
	return list;
}
