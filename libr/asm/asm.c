/* radare - LGPL - Copyright 2009-2025 - pancake, nibble */

// needed for spp
#define USE_R2 1
#include <r_core.h>
#include <spp/spp.h>
#include <config.h>

R_LIB_VERSION(r_asm);

static RAsmPlugin *asm_static_plugins[] = { R_ASM_STATIC_PLUGINS };

static const char *directives[] = {
	".include", ".error", ".warning",
	".echo", ".if", ".ifeq", ".endif",
	".else", ".set", ".get", ".extern", NULL
};

R_API bool r_asm_plugin_add(RAsm *a, RAsmPlugin *foo) {
	R_RETURN_VAL_IF_FAIL (a && foo, false);
	RAsmPluginSession *aps = R_NEW0 (RAsmPluginSession);
	aps->rasm = a;
	aps->plugin = foo;
	aps->data = NULL; // to be used by the plugin
	r_list_append (a->sessions, aps);
	return true;
}

R_API bool r_asm_plugin_remove(RAsm *a, RAsmPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (a && plugin, false);
	RListIter *iter;
	RAsmPluginSession *aps;
	r_list_foreach (a->sessions, iter, aps) {
		if (aps->plugin == plugin) {
			if (aps == a->cur) {
				a->cur = NULL;
			}
			if (aps->plugin->fini) {
				aps->plugin->fini (aps);
			}
			r_list_delete (a->sessions, iter);
			return true;
		}
	}
	return false;
}

/* pseudo.c - private api */
static int r_asm_pseudo_align(RAsmCode *acode, RAnalOp *op, const char *input) {
	acode->code_align = r_num_math (NULL, input);
	return 0;
}

static int r_asm_pseudo_string(RAnalOp *op, char *input, bool zero) {
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
	len = r_str_unescape (input) + (zero? 1: 0);
	r_anal_op_set_mnemonic (op, op->addr, input);
	r_anal_op_set_bytes (op, op->addr, (const ut8 *)input, len + 1);
	return len;
}

static int r_asm_pseudo_intN(RAsm *a, RAnalOp *op, char *input, int n, bool is_unsigned) {
	short s;
	int i;
	long int l;
	ut64 s64 = r_num_math (NULL, input);
	if (is_unsigned) {
		if (n != 8 && s64 >> (n * 8)) {
			R_LOG_ERROR ("uint%d out of range", n * 8);
			return -1;
		}
	} else {
		st64 val = (st64)s64;
		st64 max, min;
		if (n == 8) {
			max = LLONG_MAX;
			min = LLONG_MIN;
		} else {
			max = (1LL << (n * 8 - 1)) - 1;
			min = - (1LL << (n * 8 - 1));
		}
		if (val < min || val > max) {
			R_LOG_ERROR ("int%d value %" PFMT64d " out of range (%" PFMT64d " to %" PFMT64d ")", n * 8, val, min, max);
			return -1;
		}
	}
	ut8 *buf = malloc (8);
	if (!buf) {
		return 0;
	}
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	if (is_unsigned) {
		if (n == 1) {
			buf[0] = (ut8)s64;
		} else if (n == 2) {
			r_write_ble16 (buf, (ut16)s64, be);
		} else if (n == 4) {
			r_write_ble32 (buf, (ut32)s64, be);
		} else if (n == 8) {
			r_write_ble64 (buf, s64, be);
		} else {
			free (buf);
			return 0;
		}
	} else {
		if (n == 1) {
			buf[0] = (ut8) (st64)s64;
		} else if (n == 2) {
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
	}
	r_anal_op_set_bytes (op, op->addr, buf, n);
	free (buf);
	return n;
}

static int r_asm_pseudo_float(RAsm *a, RAnalOp *op, char *input, const RCFloatProfile *profile) {
	R_RETURN_VAL_IF_FAIL (a && op && input && profile, -1);
	ut8 buf[16];
	double value = strtod (r_str_trim_head_ro (input), NULL);
	const int total_bits = profile->sign_bits + profile->exp_bits + profile->mant_bits;
	const int byte_size = (total_bits + 7) / 8;
	if (byte_size > sizeof (buf)) {
		R_LOG_ERROR ("Too many bits");
		return -1;
	}
	bool success = r_cfloat_write (value, profile, buf, byte_size);
	if (success) {
		r_anal_op_set_bytes (op, op->addr, buf, byte_size);
		return byte_size;
	}
	return -1;
}

static int r_asm_pseudo_byte(RAnalOp *op, char *input) {
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
		if (num < 0 || num > 255) {
			R_LOG_ERROR ("byte value %d out of range (0-255)", num);
			free (buf);
			return -1;
		}
		buf[i] = num;
	}
	r_anal_op_set_bytes (op, 0, buf, len);
	free (buf);
	return len;
}

static int r_asm_pseudo_fill(RAnalOp *op, const char *input) {
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
			r_anal_op_set_bytes (op, 0, buf, size);
			free (buf);
		}
	} else {
		size = 0;
	}
	return size;
}

static int r_asm_pseudo_incbin(RAnalOp *op, char *input) {
	size_t bytes_read = 0;
	r_str_replace_char (input, ',', ' ');
	// int len = r_str_word_count (input);
	r_str_word_set0 (input);
	// const char *filename = r_str_word_get0 (input, 0);
	size_t skip = (size_t)r_num_math (NULL, r_str_word_get0 (input, 1));
	size_t count = (size_t)r_num_math (NULL, r_str_word_get0 (input, 2));
	char *content = r_file_slurp (input, &bytes_read);
	if (!content) {
		R_LOG_ERROR ("Could not open '%s'", input);
		return -1;
	}
	if (skip > 0) {
		skip = skip > bytes_read? bytes_read: skip;
	}
	if (count > 0) {
		count = count > bytes_read? 0: count;
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
	a->codealign = 1;
	a->dataalign = 1;
	a->pseudo = false;
	a->use_spp = false;
	a->sessions = r_list_newf (free);
	a->config = r_arch_config_new ();
	a->parse = r_parse_new ();
	size_t i;
	for (i = 0; asm_static_plugins[i]; i++) {
		r_asm_plugin_add (a, asm_static_plugins[i]);
	}
	return a;
}

R_API void r_asm_free(RAsm *a) {
	if (!a) {
		return;
	}
	// r_unref (a->config);
	r_unref (a->config);
	r_syscall_free (a->syscall);
	sdb_free (a->pair);
	ht_pp_free (a->flags);
	a->pair = NULL;
	RListIter *iter;
	RAsmPluginSession *aps;
	r_list_foreach (a->sessions, iter, aps) {
		RAsmParseFini fini = aps->plugin->fini;
		if (fini) {
			fini (aps);
		}
	}
	r_list_free (a->sessions);
	r_parse_free (a->parse);
	free (a);
}

R_API void r_asm_set_user_ptr(RAsm *a, void *user) {
	a->user = user;
	a->parse->user = user;
}

R_API bool r_asm_use_assembler(RAsm *a, const char *name) {
	R_RETURN_VAL_IF_FAIL (a && name, false);
	// TODO not implemented
	return false;
}

static char *predotname(const char *name) {
	char *sname = strdup (name);
	char *dot = strchr (sname, '.');
	if (dot) {
		*dot = 0;
	}
	return sname;
}

static void useparser(RAsm *a, RAsmPluginSession *aps) {
	RAsmPlugin *h = aps->plugin;
	if (a->cur) {
		if (a->cur == aps) {
			return;
		}
		if (h->init && !aps->data) {
			h->init (aps);
		}
	}
	a->cur = aps;
}

R_API bool r_asm_use_parser(RAsm *a, const char *name) {
	R_RETURN_VAL_IF_FAIL (a && name, false);
	if (r_str_startswith (name, "r2ghidra")) {
		// This plugin uses asm.cpu as a hack, ignoring
		return false;
	}
	// TODO: remove the alias workarounds because of missing pseudo plugins
	if (r_str_startswith (name, "s390.")) {
		name = "x86";
	} else if (r_str_startswith (name, "loongarch")) {
		name = "mips";
	} else if (r_str_startswith (name, "blackfin")) {
		name = "arm";
	} else if (r_str_startswith (name, "sbpf")) {
		// Use BPF pseudo parser for sBPF as fallback
		name = "bpf";
	}

	RListIter *iter;
	RAsmPluginSession *aps;
	r_list_foreach (a->sessions, iter, aps) {
		RAsmPlugin *ap = aps->plugin;
		if (!strcmp (ap->meta.name, name)) {
			useparser (a, aps);
			return true;
		}
	}
	bool found = false;
	if (strchr (name, '.')) {
		char *sname = predotname (name);
		r_list_foreach (a->sessions, iter, aps) {
			RAsmPlugin *ap = aps->plugin;
			char *shname = predotname (ap->meta.name);
			found = !strcmp (shname, sname);
			free (shname);
			if (found) {
				useparser (a, aps);
				break;
			}
		}
		free (sname);
	} else {
		// Try to match arch name with arch.pseudo pattern
		char *dotname = r_str_newf ("%s.pseudo", name);
		if (dotname) {
			r_list_foreach (a->sessions, iter, aps) {
				RAsmPlugin *ap = aps->plugin;
				if (!strcmp (ap->meta.name, dotname)) {
					useparser (a, aps);
					found = true;
					break;
				}
			}
			free (dotname);
		}
	}
	if (!found) {
		R_LOG_WARN ("Cannot find asm.parser for %s", name);
		RAsmPlugin *pcur = R_UNWRAP3 (a, cur, plugin);
		if (pcur && pcur->meta.name) {
			if (r_str_startswith (pcur->meta.name, "null")) {
				return false;
			}
		}
		// check if p->cur
		r_list_foreach (a->sessions, iter, aps) {
			RAsmPlugin *h = aps->plugin;
			if (r_str_startswith (h->meta.name, "null")) {
				R_LOG_INFO ("Fallback to null");
				useparser (a, aps);
				return false;
			}
		}
		return false;
	}
	return true;
}

static void load_asm_descriptions(RAsm *a) {
	const char *arch = a->config->arch;
	if (!arch || !strcmp (arch, "any")) {
		arch = a->config->cpu;
	}
	if (!strcmp (arch, "sbpf")) {
		arch = "bpf";
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
	R_RETURN_VAL_IF_FAIL (a, false);
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
			return true;
		}
	//	R_LOG_ERROR ("Cannot find '%s' arch plugin. See rasm2 -L or -LL", name);
	}
	return false;
}

#if 0
// R2_600
// XXX this is r_arch
R_DEPRECATE R_API void r_asm_set_cpu(RAsm *a, const char *cpu) {
	R_RETURN_IF_FAIL (a);
	r_arch_config_set_cpu (a->config, cpu);
}
#endif

R_DEPRECATE R_API int r_asm_set_bits(RAsm *a, int bits) {
	a->config->bits = bits;
	return true;
}

R_API bool r_asm_set_big_endian(RAsm *a, bool b) {
	R_RETURN_VAL_IF_FAIL (a, false);
#if 0
	if (a->cur) {
		switch (a->cur->endian) {
		case R_SYS_ENDIAN_NONE:
		case R_SYS_ENDIAN_BI:
			// TODO: not yet implemented
			a->config->big_endian = b? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;
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
	// a->config->endian = R_SYS_ENDIAN? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE; // default is host endian
	if (a->arch) {
		r_arch_set_endian (a->arch, a->config->endian);
	}
	a->config->endian = b? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;
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
	R_RETURN_VAL_IF_FAIL (a && buf && op, -1);
	r_anal_op_init (op);
	if (len < 1) {
		return 0;
	}

	int ret = 0;
	op->size = 4;
	// r_anal_op_set_mnemonic (op, op->addr, "");
	if (a->config->codealign) {
		const int mod = a->pc % a->config->codealign;
		if (mod) {
			r_anal_op_set_mnemonic (op, op->addr, "unaligned");
			op->size = a->config->codealign - mod;
			return -1;
		}
	}
	if (a->analb.anal) {
		ret = a->analb.decode (a->analb.anal, op, a->pc, buf, len,
			R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_DISASM);
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
	if (a->pseudo) {
		char *newtext = r_asm_parse_pseudo (a, op->mnemonic);
		if (newtext) {
			r_anal_op_set_mnemonic (op, op->addr, newtext);
			free (newtext);
		}
	}
	int opsz = (op->size > 0)? R_MAX (0, R_MIN (len, op->size)): 1;
	r_anal_op_set_bytes (op, op->addr, buf, opsz);
	return ret;
}

typedef int(*Ase)(RAsm *a, RAnalOp *op, const char *buf);

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

// returns instruction size.. but we have the size in analop and should return bool because thats just a wrapper around analb.encode
static int r_asm_assemble_single(RAsm *a, RAnalOp *op, const char *buf) {
	R_RETURN_VAL_IF_FAIL (a && op && buf, 0);
	int ret = 0;
	char *b = strdup (buf);
	if (!b) {
		return 0;
	}
	r_str_case (b, false); // to-lower
	if (a->analb.anal) {
		ut8 buf[256] = { 0 };
		a->analb.anal->arch->cfg->endian = a->config->endian;
		// XXX we should use just RArch and ecur/dcur
		ret = a->analb.encode (a->analb.anal, a->pc, b, buf, sizeof (buf));
		if (ret > 0) {
			r_anal_op_set_bytes (op, a->pc, buf, R_MIN (ret, sizeof (buf)));
		}
	} else {
		R_LOG_ERROR ("Cannot assemble because there are no anal binds into the asm instance %p", a);
		ret = -1;
#if 0
	} else if (ase) {
		/* find callback if no assembler support in current plugin */
		ret = ase (a, op, b);
#endif
	}
	free (b);
	return ret;
}

R_API RAsmCode *r_asm_mdisassemble(RAsm *a, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (a && buf && len >= 0, NULL);

	ut64 pc = a->pc;
	ut64 idx;
	int ret;
	// XXX move from io to archconfig!! and remove the dependency on core!
	const size_t addrbytes = a->user? ((RCore *)a->user)->io->addrbytes: 1;
	int mininstrsize = 1; // TODO: use r_arch_info ();

	RAsmCode *acode = r_asm_code_new ();
	if (!acode) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new (NULL);
	acode->bytes = r_mem_dup (buf, len);

	for (idx = 0; idx + addrbytes <= len; idx += (addrbytes * ret)) {
		RAnalOp op = { 0 };
		r_anal_op_init (&op);
		r_asm_set_pc (a, pc + idx);
		// we can change this to return RAnalOp* instead of passing it as arg here
		ret = r_asm_disassemble (a, &op, buf + idx, len - idx);
		if (ret < 1) {
			ret = mininstrsize;
		}
		ret = op.size;
		if (a->pseudo) {
			char *newtext = r_asm_parse_pseudo (a, op.mnemonic);
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

R_API RAsmCode *r_asm_mdisassemble_hexstr(RAsm *a, RParse *p, const char *hexstr) {
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
		char *res = r_asm_parse_pseudo (a, ret->assembly);
		if (res) {
			free (ret->assembly);
			ret->assembly = res;
		}
	}
	free (buf);
	return ret;
}

static void htpp_freekv(HtPPKv *kv) {
	if (kv) {
		free (kv->key);
		free (kv->value);
		// 	free (kv); // causes double free
	}
}

static void *htpp_strdup(const void *v) {
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
			void *p = r_lib_dl_open ("libr_core." R_LIB_EXT, false);
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
	} else if (r_str_startswith (ptr, ".asciiz")) {
		if (isspace (ptr[7])) {
			char *str = r_str_trim_dup (ptr + 8);
			ret = r_asm_pseudo_string (op, ptr + 8, true);
			free (str);
		} else {
			R_LOG_ERROR ("Unknown directive %s. use .ascii or .asciiz", ptr);
		}
	} else if (r_str_startswith (ptr, ".ascii")) {
		if (isspace (ptr[6])) {
			char *str = r_str_trim_dup (ptr + 7);
			ret = r_asm_pseudo_string (op, ptr + 7, false);
			free (str);
		} else {
			R_LOG_ERROR ("Unknown directive %s. use .ascii or .asciiz", ptr);
		}
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
		if (! (r_asm_set_bits (a, r_num_math (NULL, ptr + 6)))) {
			R_LOG_ERROR ("Unsupported value for .bits");
			ret = -1;
		} else {
			ret = 0;
		}
	} else if (r_str_startswith (ptr, ".fill ")) {
		ret = r_asm_pseudo_fill (op, ptr + 6);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".kernel ")) {
		r_syscall_setup (a->syscall, a->config->arch, a->config->bits, asmcpu, ptr + 8);
	} else if (r_str_startswith (ptr, ".cpu ")) {
		r_arch_config_set_cpu (a->config, ptr + 5);
	} else if (r_str_startswith (ptr, ".os ")) {
		r_syscall_setup (a->syscall, a->config->arch, a->config->bits, asmcpu, ptr + 4);
	} else if (r_str_startswith (ptr, ".hex ")) {
		ut8 *bytes = malloc (strlen (ptr + 5) / 2);
		int size = r_hex_str2bin (ptr + 5, bytes);
		ret = r_anal_op_set_bytes (op, 0, bytes, size)? size: 0;
		free (bytes);
	} else if (r_str_startswith (ptr, ".byte ") || r_str_startswith (ptr, ".int8 ")) {
		ret = r_asm_pseudo_byte (op, ptr + 6);
		if (ret < 0) {
			return ret;
		}
	} else if ((r_str_startswith (ptr, ".int16 ")) || r_str_startswith (ptr, ".short ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 2, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".int32 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 4, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".int64 ")) {
		char *str = r_asm_code_equ_replace (acode, ptr + 7);
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 8, false);
		free (str);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".db ")) {
		ret = r_asm_pseudo_byte (op, ptr + 4);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".word ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 6, 2, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".dw ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 4, 2, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".dword ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 4, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".dd ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 4, 4, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".qword ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 8, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".dq ")) {
		char *str = r_asm_code_equ_replace (acode, ptr + 4);
		ret = r_asm_pseudo_intN (a, op, ptr + 4, 8, false);
		free (str);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".uint8 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 1, true);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".uint16 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 8, 2, true);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".uint32 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 8, 4, true);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".uint64 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 8, 8, true);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".size")) {
		ret = 0; // do nothing, ignored
	} else if (r_str_startswith (ptr, ".section")) {
		ret = 0; // do nothing, ignored
	} else if (r_str_startswith (ptr, ".glob")) {
		// .global .globl
		R_LOG_DEBUG (".global directive does nothing for now");
		ret = 0;
	} else if (r_str_startswith (ptr, ".equ ")) {
		char *arg = (char *)r_str_trim_head_ro (ptr + 5);
		ptr2 = strchr (arg, ',');
		if (!ptr2) {
			ptr2 = strchr (arg, '=');
		}
		if (!ptr2) {
			ptr2 = strchr (arg, ' ');
		}
		if (ptr2) {
			*ptr2 = '\0';
			r_asm_code_set_equ (acode, arg, ptr2 + 1);
			*ptr2 = ' ';
			ret = 0;
		} else {
			R_LOG_ERROR ("Invalid syntax for '.equ': Use '.equ <word>=<word>'");
		}
	} else if (r_str_startswith (ptr, ".org ")) {
		r_asm_set_pc (a, r_num_math (NULL, ptr + 5));
		ret = 0;
		*off = a->pc;
	} else if (r_str_startswith (ptr, ".offset ")) {
		R_LOG_ERROR ("Invalid use of the .offset directory. This directive is only supported in r2 -c 'waf'");
	} else if (r_str_startswith (ptr, ".text")) {
		acode->code_offset = a->pc;
		ret = 0;
	} else if (r_str_startswith (ptr, ".data")) {
		acode->data_offset = a->pc;
		ret = 0;
	} else if (r_str_startswith (ptr, ".cfloat ")) {
		char *args = r_str_trim_dup (ptr + strlen (".cfloat "));
		ret = -1;
		if (args) {
			if (r_str_word_count (args) == 6) {
				ret = 0;
			} else {
				R_LOG_ERROR ("The .cfloat directive expects 6 arguments: (sign_bits, exp_bits, mant_bits, bias, big_endian, explicit_leading_bit)");
				R_LOG_INFO ("Example (float): .cfloat 1 8 23 127 0 0");
				R_LOG_INFO ("Example (double): .cfloat 1 11 52 1023 0 0");
				R_LOG_INFO ("Example (bf16): .cfloat 1 8 7 127 0 0");
				R_LOG_INFO ("Example (x86-80): .cfloat 1 15 64 16383 0 1");
			}
		}
		if (ret == 0) {
			r_str_word_set0 (args);
			RCFloatProfile fp = {
				.sign_bits = atoi (r_str_word_get0 (args, 0)),
				.exp_bits = atoi (r_str_word_get0 (args, 1)),
				.mant_bits = atoi (r_str_word_get0 (args, 2)),
				.bias = atoi (r_str_word_get0 (args, 3)),
				.big_endian = atoi (r_str_word_get0 (args, 4)),
				.explicit_leading_bit = atoi (r_str_word_get0 (args, 5))
			};
			acode->cfloat_profile = fp;
		}
		free (args);
	} else if (r_str_startswith (ptr, ".float ")) {
		const bool be = (a->config->big_endian & R_SYS_ENDIAN_BIG);
		acode->cfloat_profile.big_endian = be;
		// acode->cfloat_profile.big_endian = false;
		ret = r_asm_pseudo_float (a, op, ptr + 7, &acode->cfloat_profile);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".double ")) {
		const bool be = (a->config->big_endian & R_SYS_ENDIAN_BIG);
		RCFloatProfile profile = { 1, 11, 52, 1023, be, false };
		ret = r_asm_pseudo_float (a, op, ptr + 8, &profile);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".bf16 ")) {
		RCFloatProfile profile = { 1, 8, 7, 127, false, false };
		ret = r_asm_pseudo_float (a, op, ptr + 6, &profile);
		if (ret < 0) {
			return ret;
		}
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

R_API RAsmCode *r_asm_assemble(RAsm *a, const char *assembly) {
	int num, stage, ret, idx, ctr, i, linenum = 0;
	char *ptr = NULL, *ptr_start = NULL;
	RAnalOp op = { 0 };
	ut64 off, pc;

	char *buf_token = NULL;
	size_t tokens_size = 32;
	char **tokens = calloc (sizeof (char *), tokens_size);
	if (!tokens) {
		return NULL;
	}
	if (!assembly) {
		free (tokens);
		return NULL;
	}
	ht_pp_free (a->flags);
	if (! (a->flags = ht_pp_new (htpp_strdup, htpp_freekv, NULL))) {
		free (tokens);
		return NULL;
	}
	RAsmCode *acode = r_asm_code_new ();
	if (!acode) {
		free (tokens);
		return NULL;
	}
	acode->assembly = strdup (assembly);
	acode->bytes = calloc (1, 64);

	char *lbuf = strdup (assembly);
	if (a->use_spp) {
		Output out = {
			.fout = NULL,
			.cout = r_strbuf_new ("")
		};
		r_strbuf_init (out.cout);
		struct Proc proc;
		spp_proc_set (&proc, "spp", 1);

		lbuf = replace_directives (lbuf);
		spp_eval (lbuf, &out);
		free (lbuf);
		lbuf = strdup (r_strbuf_get (out.cout));
		r_strbuf_free (out.cout);
	}
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
		snprintf (val, sizeof (val), "0x%" PFMT64x, a->pc);
		lbuf = r_str_replace (lbuf, "$$", val, 1);
	}
	if (a->syscall) {
		char val[32];
		char *aa, *p = strstr (lbuf, "$sys.");
		while (p) {
			char *sp = (char *)r_str_closer_chr (p, " \n\r#");
			if (sp) {
				char osp = *sp;
				*sp = 0;
				aa = strdup (p);
				*sp = osp;
				num = r_syscall_get_num (a->syscall, aa + 5);
				snprintf (val, sizeof (val), "%d", num);
				lbuf = r_str_replace (lbuf, aa, val, 1);
				free (aa);
			}
			p = strstr (p + 5, "$sys.");
		}
	}
	bool labels = !!strchr (lbuf, ':');

	/* Tokenize */
	for (tokens[0] = lbuf, ctr = 0; (ptr = next_token (tokens[ctr]));) {
		if (ctr + 1 >= tokens_size) {
			const size_t new_tokens_size = tokens_size * 2;
			if (sizeof (char *) * new_tokens_size <= sizeof (char *) * tokens_size) {
				// overflow
				R_LOG_ERROR ("Too many tokens");
				goto fail;
			}
			char **new_tokens = realloc (tokens, sizeof (char *) * new_tokens_size);
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

#define isavrseparator(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r' || (x) == ' ' || \
	(x) == ',' || (x) == ';' || (x) == '[' || (x) == ']' || \
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
		linenum = 0;
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
				for (ptr_start = buf_token; *ptr_start && isavrseparator (*ptr_start); ptr_start++)
					;
			} else {
				for (ptr_start = buf_token; *ptr_start && IS_SEPARATOR (*ptr_start); ptr_start++)
					;
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
				char *cptr = strchr (ptr_start, ',');
				ptr = strchr (ptr_start, '#');
				// a comma is probably not followed by a comment
				// 8051 often uses #symbol notation as 2nd arg
				if (cptr && ptr && cptr < ptr) {
					likely_comment = false;
					for (cptr += 1; cptr < ptr; cptr += 1) {
						if (!isspace ((int)*cptr)) {
							likely_comment = true;
							break;
						}
					}
				}
				// # followed by number literal also
				// isn't likely to be a comment
				likely_comment = likely_comment && ptr && !R_BETWEEN ('0', ptr[1], '9') && ptr[1] != '-';
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
					// if (stage != 2) {
					if (ptr_start[1] && ptr_start[1] != ' ') {
						*ptr = 0;
						char *p = strdup (ptr_start);
						*ptr = ':';
						if (acode->code_align) {
							off += (acode->code_align - (off % acode->code_align));
						}
						char *food = r_str_newf ("0x%" PFMT64x, off);
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
				if (!*ptr_start) {
					continue;
				}
				str = r_asm_code_equ_replace (acode, ptr_start);
				ret = r_asm_assemble_single (a, &op, str);
				free (str);
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
				acode->bytes = (ut8 *)newbuf;
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
	r_anal_op_fini (&op);
	return acode;
fail:
	free (lbuf);
	free (tokens);
	r_anal_op_fini (&op);
	r_asm_code_free (acode);
	return NULL;
}

R_API char *r_asm_describe(RAsm *a, const char *str) {
	return (a && a->pair)? sdb_get (a->pair, str, 0): NULL;
}

/* to ease the use of the native bindings (not used in r2) */
R_API char *r_asm_tostring(RAsm *a, ut64 addr, const ut8 *b, int l) {
	R_RETURN_VAL_IF_FAIL (a && b && l >= 0, NULL);
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
	RAsmCode *code = r_asm_assemble (a, b);
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
	R_RETURN_VAL_IF_FAIL (name, -1);
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
	R_RETURN_VAL_IF_FAIL (a, NULL);
	// should use rarch instead!.. but for now ranal.mnemonics is calling arch.mnemonics..
	if (a->analb.anal && a->analb.mnemonics) {
		return a->analb.mnemonics (a->analb.anal, id, json);
	}
	return NULL;
}

R_API int r_asm_mnemonics_byname(RAsm *a, const char *name) {
	R_RETURN_VAL_IF_FAIL (a && name, 0);
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

R_API RList *r_asm_cpus(RAsm *a) {
	R_RETURN_VAL_IF_FAIL (a, NULL);
	// R2_600 move to r_arch api instead?
	const char *cpus = R_UNWRAP5 (a, arch, session, plugin, cpus);
	RList *list = cpus
		? r_str_split_duplist (cpus, ",", 0)
		: r_list_newf (free);
	r_list_sort (list, (RListComparator)strcmp);
	return list;
}

R_API char *r_asm_parse(RAsm *a, const char *s, int what) {
	char *res = strdup (s);
	if (what & R_PARSE_FILTER_IMMTRIM) {
		char *newres = r_asm_parse_immtrim (a, s);
		if (newres) {
			free (res);
			res = newres;
		}
	}
	if (what & R_PARSE_FILTER_SUBVAR) {
		// ut64 addr = a->pc;
		// r_asm_parse_subvar (a, f, addr, oplen, ..)
	}
	if (what & R_PARSE_FILTER_PSEUDO) {
		char *newres = r_asm_parse_pseudo (a, s);
		if (newres) {
			free (res);
			res = newres;
		}
	}
	if (what & R_PARSE_FILTER_COLOR) {
		// TODO
	}
	return res;
}
