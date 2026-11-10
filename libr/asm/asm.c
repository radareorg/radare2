/* radare - LGPL - Copyright 2009-2026 - pancake, nibble */

// needed for spp
#define USE_R2 1
#include <r_core.h>
#include <spp/spp.h>
#include <config.h>
#include "r2plugins.h"

R_LIB_VERSION(r_asm);

static RAsmPlugin *asm_static_plugins[] = { R_ASM_STATIC_PLUGINS };

static const char *directives[] = {
	".include", ".error", ".warning", ".echo", ".if", ".ifeq", ".endif", ".else", ".set", ".get", NULL
};

R_API bool r_asm_plugin_add(RAsm *a, RAsmPlugin *foo) {
	R_RETURN_VAL_IF_FAIL (a && foo, false);
	RAsmPluginSession *aps = R_NEW0 (RAsmPluginSession);
	aps->rasm = a;
	aps->plugin = foo;
	aps->data = NULL; // to be used by the plugin
	r_list_append (a->libstore->plugins, aps);
	return true;
}

R_API bool r_asm_plugin_remove(RAsm *a, RAsmPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (a && plugin, false);
	RListIter *iter;
	RAsmPluginSession *aps;
	r_list_foreach (a->libstore->plugins, iter, aps) {
		if (aps->plugin == plugin) {
			if (aps == a->cur) {
				a->cur = NULL;
			}
			if (aps->plugin->fini) {
				aps->plugin->fini (aps);
			}
			r_list_delete (a->libstore->plugins, iter);
			return true;
		}
	}
	return false;
}

/* pseudo.c - private api */

// data directives can emit more than the 64 bytes r_anal_op_set_bytes() keeps
static int asm_op_set_data(RAnalOp *op, const ut8 *data, int size) {
	if (size < 1) {
		return 0;
	}
	if (op->weakbytes) {
		op->weakbytes = false;
	} else if (op->bytes != op->bytes_buf) {
		free (op->bytes);
	}
	op->bytes = data? r_mem_dup (data, size): malloc (size);
	op->size = op->bytes? size: 0;
	return op->bytes? size: -1;
}

static int asm_op_set_padding(RAnalOp *op, ut64 size, ut8 fill, bool last_stage) {
	if (size > INT_MAX) {
		R_LOG_ERROR ("Too large padding");
		return -1;
	}
	if (!size || !last_stage) {
		return (int)size;
	}
	int len = asm_op_set_data (op, NULL, (int)size);
	if (!len) {
		return -1;
	}
	memset (op->bytes, fill, len);
	return len;
}

static bool asm_parse_fill_byte(const char *input, const char *directive, ut8 *fill) {
	const char *err = NULL;
	const char *arg = r_str_trim_head_ro (input);
	ut64 value = r_num_math_err (NULL, arg, &err);
	if (!*arg) {
		err = "missing value";
	}
	if (err) {
		R_LOG_ERROR ("Invalid fill for %s: %s", directive, err);
		return false;
	}
	if (value > UT8_MAX) {
		R_LOG_ERROR ("%s fill must be a byte (0-255)", directive);
		return false;
	}
	*fill = (ut8)value;
	return true;
}

static int r_asm_pseudo_align(RAsm *a, RAsmCode *acode, RAnalOp *op, char *input, ut8 fill, bool last_stage) {
	char *comma = strchr (input, ',');
	if (comma) {
		*comma = 0;
		if (strchr (comma + 1, ',')) {
			R_LOG_ERROR ("Invalid usage of .align boundary[,fill]");
			return -1;
		}
		if (!asm_parse_fill_byte (comma + 1, ".align", &fill)) {
			return -1;
		}
	}
	const char *err = NULL;
	const char *arg = r_str_trim_head_ro (input);
	ut64 boundary = r_num_math_err (NULL, arg, &err);
	if (!*arg) {
		err = "missing boundary";
	}
	if (err) {
		R_LOG_ERROR ("Invalid alignment: %s", err);
		return -1;
	}
	acode->code_align = (int)boundary;
	if (boundary < 2) {
		return 0;
	}
	const ut64 mod = a->pc % boundary;
	return asm_op_set_padding (op, mod? boundary - mod: 0, fill, last_stage);
}

typedef struct {
	RMuta *muta;
	RMutaSession *encoder;
} AsmCharset;

static bool asm_directive(const char *input, const char *name) {
	size_t len = strlen (name);
	return !strncmp (input, name, len) && (!input[len] || isspace ((ut8)input[len]));
}

static int asm_parse_string(char *input, char **text) {
	input = (char *)r_str_trim_head_ro (input);
	if (*input != '"') {
		R_LOG_ERROR ("Expected a quoted string");
		return -1;
	}
	char *end = input + 1;
	for (; *end && *end != '"'; end++) {
		if (*end == '\\') {
			if (end[1] == 'x' && (!isxdigit ((ut8)end[2]) || !isxdigit ((ut8)end[3]))) {
				R_LOG_ERROR ("Invalid hex escape in string");
				return -1;
			}
			if (end[1]) {
				end++;
			}
		}
	}
	if (*end != '"' || *r_str_trim_head_ro (end + 1) || end - input > INT_MAX) {
		R_LOG_ERROR ("Invalid quoted string");
		return -1;
	}
	*end = 0;
	*text = input + 1;
	return r_str_unescape (*text);
}

static int asm_set_charset(AsmCharset *state, char *input) {
	char *name;
	int len = asm_parse_string (input, &name);
	if (len < 0) {
		return -1;
	}
	if (!len || strlen (name) != len) {
		R_LOG_ERROR ("Invalid charset name");
		return -1;
	}
	r_muta_session_free (state->encoder);
	state->encoder = NULL;
	if (!strcmp (name, "raw")) {
		return 0;
	}
	if (!state->muta) {
		state->muta = r_muta_new ();
	}
	state->encoder = r_muta_use (state->muta, name);
	if (!state->encoder || !state->encoder->h->encode) {
		R_LOG_ERROR ("Unknown or unsupported assembly charset '%s'", name);
		return -1;
	}
	return 0;
}

static int r_asm_pseudo_string(RAnalOp *op, AsmCharset *state, char *input, bool zero) {
	char *text;
	int len = asm_parse_string (input, &text);
	if (len < 0) {
		return -1;
	}
	ut8 *encoded = NULL;
	const ut8 *data = (const ut8 *)text;
	if (state->encoder) {
		int consumed = 0;
		int size = state->encoder->h->encode (state->encoder, data, len, &encoded, &consumed);
		if (size < 0 || consumed != len || (size && !encoded)) {
			R_LOG_ERROR ("Cannot encode string with '%s' at byte %d", state->encoder->h->meta.name, consumed);
			free (encoded);
			return -1;
		}
		data = encoded;
		len = size;
	}
	int size = -1;
	if (!zero || len < INT_MAX) {
		size = asm_op_set_data (op, NULL, len + (zero? 1: 0));
		if (size > 0) {
			if (len) {
				memcpy (op->bytes, data, len);
			}
			if (zero) {
				op->bytes[len] = 0;
			}
		}
	}
	free (encoded);
	r_anal_op_set_mnemonic (op, op->addr, text);
	return size;
}

static bool asm_eval_operand(const char *arg, size_t len, char *expression, const char *directive, ut64 *value) {
	while (len && isspace ((ut8)*arg)) {
		arg++;
		len--;
	}
	while (len && isspace ((ut8)arg[len - 1])) {
		len--;
	}
	if (!len) {
		R_LOG_ERROR ("Missing expression in %s", directive);
		return false;
	}
	expression[0] = '(';
	memcpy (expression + 1, arg, len);
	expression[len + 1] = ')';
	expression[len + 2] = 0;
	const char *err = NULL;
	*value = r_num_math_err (NULL, expression, &err);
	if (err) {
		R_LOG_ERROR ("Invalid number in %s: %s", directive, err);
		return false;
	}
	return true;
}

static bool asm_int_in_range(ut64 value, int n, bool is_unsigned) {
	if (is_unsigned) {
		if (n != 8 && value >> (n * 8)) {
			R_LOG_ERROR ("uint%d out of range", n * 8);
			return false;
		}
		return true;
	}
	if (n == 8) {
		return true;
	}
	const st64 val = (st64)value;
	const st64 max = (1LL << (n * 8 - 1)) - 1;
	const st64 min = -(1LL << (n * 8 - 1));
	if (val < min || val > max) {
		R_LOG_ERROR ("int%d value %" PFMT64d " out of range (%" PFMT64d " to %" PFMT64d ")", n * 8, val, min, max);
		return false;
	}
	return true;
}

static int r_asm_pseudo_intN(RAsm *a, RAnalOp *op, const char *input, int n, bool is_unsigned, bool last_stage, bool is_byte) {
	int count = 1;
	const char *p = input;
	for (; *p; p++) {
		count += *p == ',';
	}
	ut64 size;
	if (r_mul_overflow ((ut64)count, (ut64)n, &size) || size > INT_MAX) {
		return -1;
	}
	if (!last_stage) {
		return (int)size;
	}
	if (asm_op_set_data (op, NULL, (int)size) < 0) {
		return -1;
	}
	const size_t inputlen = p - input;
	char stack[128];
	char *expression = inputlen <= sizeof (stack) - 3? stack: malloc (inputlen + 3);
	if (!expression) {
		return -1;
	}
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	const char *arg = input;
	int i;
	for (i = 0; i < count; i++) {
		const char *end = strchr (arg, ',');
		if (!end) {
			end = input + inputlen;
		}
		ut64 value;
		if (!asm_eval_operand (arg, end - arg, expression, is_byte? ".byte": ".intN", &value)) {
			break;
		}
		if (is_byte) {
			const st64 num = (st64)value;
			if (num < 0 || num > 255) {
				R_LOG_ERROR ("byte value %" PFMT64d " out of range (0-255)", num);
				break;
			}
		} else if (!asm_int_in_range (value, n, is_unsigned)) {
			break;
		}
		r_write_ble (op->bytes + i * n, value, be, n * 8);
		arg = end + 1;
	}
	if (expression != stack) {
		free (expression);
	}
	return i == count? (int)size: -1;
}

static int r_asm_pseudo_float(RAsm *a, RAnalOp *op, char *input, const RCFloatProfile *profile) {
	R_RETURN_VAL_IF_FAIL (a && op && input && profile, -1);
	ut8 buf[16];
	double value = strtod (r_str_trim_head_ro (input), NULL);
	const int total_bits = profile->sign_bits + profile->exp_bits + profile->mant_bits;
	const int byte_size = (total_bits + 7) / 8;
	if (total_bits <= 0 || byte_size <= 0) {
		R_LOG_ERROR ("Invalid .cfloat format size");
		return -1;
	}
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

static int r_asm_pseudo_fill(RAsm *a, RAnalOp *op, const char *input, ut8 fill, bool last_stage) {
	// .fill repeat[,size[,value]] like gas
	st64 repeat = 1, size = 1;
	ut32 value = 0;
	char *args = strdup (input);
	if (!args) {
		return -1;
	}
	const int nargs = r_str_split (args, ',');
	if (nargs > 3) {
		R_LOG_ERROR ("Invalid usage of .fill repeat,size,value");
		free (args);
		return -1;
	}
	const char *err = NULL;
	const char *arg = args;
	repeat = (st64)r_num_math_err (NULL, r_str_trim_head_ro (arg), &err);
	if (!err && nargs > 1) {
		arg += strlen (arg) + 1;
		size = (st64)r_num_math_err (NULL, r_str_trim_head_ro (arg), &err);
	}
	if (!err && nargs > 2) {
		arg += strlen (arg) + 1;
		value = (ut32)r_num_math_err (NULL, r_str_trim_head_ro (arg), &err);
	}
	free (args);
	if (err) {
		R_LOG_ERROR ("Invalid number in .fill: %s", err);
		return -1;
	}
	if (repeat < 0 || size < 0) {
		if (last_stage) {
			R_LOG_WARN (".fill with a negative %s is ignored", repeat < 0? "repeat": "size");
		}
		return 0;
	}
	ut64 total;
	if (r_mul_overflow ((ut64)repeat, (ut64)size, &total) || total > INT_MAX) {
		R_LOG_ERROR ("Too large .fill");
		return -1;
	}
	if (!total) {
		return 0;
	}
	if (!last_stage) {
		return (int)total;
	}
	if (nargs < 3) {
		return asm_op_set_padding (op, total, fill, true);
	}
	ut8 *buf = calloc (1, total);
	if (!buf) {
		return -1;
	}
	ut8 pattern[sizeof (value)] = { 0 };
	r_write_ble32 (pattern, value, R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config));
	if ((size_t)size > sizeof (pattern)) {
		memcpy (buf, pattern, sizeof (pattern));
		r_mem_copyloop (buf, buf, (int)total, (int)size);
	} else {
		r_mem_copyloop (buf, pattern, (int)total, (int)size);
	}
	int len = asm_op_set_data (op, buf, (int)total);
	free (buf);
	return len;
}

static int r_asm_pseudo_org(RAsm *a, RAnalOp *op, char *input, ut64 *off, bool last_stage) {
	char *comma = strchr (input, ',');
	if (comma && (strchr (comma + 1, ',') || !*r_str_trim_head_ro (comma + 1))) {
		R_LOG_ERROR ("Invalid usage of .org address[,fill]");
		return -1;
	}
	if (comma) {
		*comma = 0;
	}
	const char *err = NULL;
	const char *address = r_str_trim_head_ro (input);
	ut64 target = r_num_math_err (NULL, address, &err);
	if (!*address) {
		err = "missing address";
	}
	if (comma) {
		*comma = ',';
	}
	if (err) {
		R_LOG_ERROR ("Invalid number for .org: %s", err);
		return -1;
	}
	if (!comma) {
		r_asm_set_pc (a, target);
		*off = a->pc;
		return 0;
	}
	ut8 fill;
	if (!asm_parse_fill_byte (comma + 1, ".org", &fill)) {
		return -1;
	}
	if (target < a->pc) {
		R_LOG_ERROR (".org with fill cannot move backwards");
		return -1;
	}
	return asm_op_set_padding (op, target - a->pc, fill, last_stage);
}

static int r_asm_pseudo_incbin(RAnalOp *op, const char *input) {
	size_t bytes_read = 0;
	// work on a copy, the directive is parsed once per stage
	char *args = strdup (input);
	if (!args) {
		return -1;
	}
	r_str_replace_char (args, ',', ' ');
	const int nargs = r_str_word_set0 (args);
	const char *filename = r_str_word_get0 (args, 0);
	const char *err = NULL;
	size_t skip = 0, count = 0;
	if (nargs > 1) {
		skip = (size_t)r_num_math_err (NULL, r_str_word_get0 (args, 1), &err);
	}
	if (!err && nargs > 2) {
		count = (size_t)r_num_math_err (NULL, r_str_word_get0 (args, 2), &err);
	}
	if (err) {
		R_LOG_ERROR ("Invalid number in .incbin: %s", err);
		free (args);
		return -1;
	}
	char *content = r_file_slurp (filename, &bytes_read);
	if (!content) {
		R_LOG_ERROR ("Could not open '%s'", filename);
		free (args);
		return -1;
	}
	free (args);
	if (skip > bytes_read) {
		skip = bytes_read;
	}
	if (count < 1 || count > bytes_read - skip) {
		count = bytes_read - skip;
	}
	if (count > INT_MAX) {
		R_LOG_ERROR ("File too large for .incbin");
		free (content);
		return -1;
	}
	int len = asm_op_set_data (op, (const ut8 *)content + skip, (int)count);
	free (content);
	return len;
}

R_API RAsm *r_asm_new(void) {
	RAsm *a = R_NEW0 (RAsm);
	a->codealign = 1;
	a->dataalign = 1;
	a->pseudo = false;
	a->use_spp = false;
	r_libstore_new (&a->libstore, a, asm_static_plugins, (RListFree)free, NULL, (RLibPluginAddCb)r_asm_plugin_add, (RLibPluginAddCb)r_asm_plugin_remove);
	a->config = r_arch_config_new ();
	a->parse = r_parse_new ();
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
	r_list_foreach (a->libstore->plugins, iter, aps) {
		RAsmParseFini fini = aps->plugin->fini;
		if (fini) {
			fini (aps);
		}
	}
	r_libstore_free (a->libstore);
	r_parse_free (a->parse);
	r_arch_free (a->arch);
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
		name = "s390";
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
	r_list_foreach (a->libstore->plugins, iter, aps) {
		RAsmPlugin *ap = aps->plugin;
		if (!strcmp (ap->meta.name, name)) {
			useparser (a, aps);
			return true;
		}
	}
	bool found = false;
	if (strchr (name, '.')) {
		char *sname = predotname (name);
		r_list_foreach (a->libstore->plugins, iter, aps) {
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
			r_list_foreach (a->libstore->plugins, iter, aps) {
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
		r_list_foreach (a->libstore->plugins, iter, aps) {
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
	if (!arch) {
		return;
	}
	if (!strcmp (arch, "sbpf")) {
		arch = "bpf";
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

static void r_asm_update_session(RAsm *a) {
	if (a->analb.anal && a->analb.anal->arch) {
		a->dcur = a->analb.anal->arch->session;
	} else if (a->arch && a->arch->session) {
		a->dcur = a->arch->session;
	} else {
		a->dcur = NULL;
	}
	a->ecur = a->dcur? (a->dcur->encoder? a->dcur->encoder: a->dcur): NULL;
}

R_API bool r_asm_use(RAsm *a, const char *name) {
	R_RETURN_VAL_IF_FAIL (a, false);
	if (R_STR_ISEMPTY (name)) {
		// that shouldnt be permitted imho, keep for backward compat
		return false;
	}
	char old_arch[sizeof (a->config->arch)] = { 0 };
	r_str_ncpy (old_arch, a->config->arch, sizeof (old_arch));
	r_arch_config_use (a->config, name);
	r_asm_use_assembler (a, name);
	if (a->analb.anal) {
		if (a->analb.use (a->analb.anal, name)) {
			r_asm_update_session (a);
			load_asm_descriptions (a);
			return true;
		}
		//	R_LOG_ERROR ("Cannot find '%s' arch plugin. See rasm2 -L or -LL", name);
	} else if (a->arch) {
		// use RArch directly without RAnal bridge
		if (r_arch_use (a->arch, a->config, name)) {
			r_asm_update_session (a);
			load_asm_descriptions (a);
			return true;
		}
	}
	a->dcur = NULL;
	a->ecur = NULL;
	r_arch_config_use (a->config, old_arch);
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

static int r_asm_disassemble_do(RAsm *a, RAnalOp *op, const ut8 *buf, int len) {
	r_anal_op_init (op);
	if (len < 1 || !a->dcur) {
		// callers expect a mnemonic even when no arch plugin is loaded
		r_anal_op_set_mnemonic (op, a->pc, "invalid");
		op->size = 1;
		return 0;
	}
	int ret = 0;
	op->size = 4;
	op->addr = a->pc;
	r_anal_op_set_bytes (op, op->addr, buf, len);
	if (a->config->codealign) {
		const int mod = a->pc % a->config->codealign;
		if (mod) {
			r_anal_op_set_mnemonic (op, op->addr, "unaligned");
			op->size = a->config->codealign - mod;
			return -1;
		}
	}
	if (r_arch_session_decode (a->dcur, op, R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_DISASM)) {
		ret = op->size;
	} else {
		op->size = 1;
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
	if (op->size < 1 || !op->mnemonic || is_invalid (op)) {
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
	op->size = R_MAX (1, op->size);
	int opsz = R_MIN (len, op->size);
	r_anal_op_set_bytes (op, op->addr, buf, opsz);
	return ret;
}

R_API int r_asm_disassemble(RAsm *a, RAnalOp *op, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (a && buf && op, -1);
	r_asm_update_session (a);
	return r_asm_disassemble_do (a, op, buf, len);
}

typedef int(*Ase)(RAsm *a, RAnalOp *op, const char *buf);

static bool is_hash_comment(const char *line, const char *hash) {
	if (R_BETWEEN ('0', hash[1], '9') || hash[1] == '-') {
		return false;
	}
	const char *comma = memchr (line, ',', hash - line);
	if (!comma) {
		return true;
	}
	for (comma++; comma < hash && isspace ((ut8)*comma); comma++) {
	}
	return comma != hash;
}

static char *asm_find_unquoted(char *str, const char *chars) {
	bool quoted = false;
	for (; *str; str++) {
		if (quoted && *str == '\\' && str[1]) {
			str++;
		} else if (*str == '"') {
			quoted = !quoted;
		} else if (!quoted && strchr (chars, *str)) {
			return str;
		}
	}
	return NULL;
}

static char *asm_prepare_source(RAsm *a, char *source) {
	char *p = source;
	while ((p = asm_find_unquoted (p, ","))) {
		if (p[1] == ',') {
			*p++ = '\n';
			*p = ' ';
		}
		p++;
	}
	char *nl = strchr (source, '\n');
	const bool semicolon_comments = nl && strchr (nl + 1, '\n');
	char *line = source;
	p = source;
	while ((p = asm_find_unquoted (p, ";#\n/"))) {
		char *end = NULL;
		if (*p == '/' && p[1] == '*') {
			end = strstr (p + 2, "*/");
			end = end? end + 2: p + strlen (p);
		} else if ((*p == ';' && semicolon_comments) || (*p == '#' && is_hash_comment (line, p))) {
			end = p + strcspn (p, "\r\n");
		}
		if (end) {
			while (p < end) {
				if (*p == '\n' || *p == '\r') {
					line = p + 1;
				} else {
					*p = ' ';
				}
				p++;
			}
		} else {
			if (*p == '\n' || *p == ';') {
				line = p + 1;
			}
			p++;
		}
	}
	RStrBuf sb = {0};
	char *start = source;
	p = source;
	while ((p = asm_find_unquoted (p, "$"))) {
		char *end = p + 1;
		char value[32];
		if (p[1] == '$') {
			end = p + 2;
			snprintf (value, sizeof (value), "0x%" PFMT64x, a->pc);
		} else if (a->syscall && r_str_startswith (p, "$sys.")) {
			end = p + strcspn (p, " \t\n\r#;");
			char saved = *end;
			*end = 0;
			int num = r_syscall_get_num (a->syscall, p + 5);
			*end = saved;
			snprintf (value, sizeof (value), "%d", num);
		} else {
			p++;
			continue;
		}
		if (!r_strbuf_append_n (&sb, start, p - start) || !r_strbuf_append (&sb, value)) {
			r_strbuf_fini (&sb);
			return NULL;
		}
		start = p = end;
	}
	if (!r_strbuf_append (&sb, start)) {
		r_strbuf_fini (&sb);
		return NULL;
	}
	return r_strbuf_drain_nofree (&sb);
}

static char *replace_directives(const char *str) {
	RStrBuf sb = {0};
	const char *p = str;
	bool block_comment = false;
	while (*p) {
		const char *line = p;
		const char *end = strchr (p, '\n');
		if (!end) {
			end = p + strlen (p);
		}
		const char *directive = NULL;
		const char *comment = end;
		bool quoted = false;
		bool leading = true;
		for (; p < end; p++) {
			if (block_comment) {
				if (*p == '*' && p + 1 < end && p[1] == '/') {
					block_comment = false;
					p++;
				}
				continue;
			}
			if (quoted) {
				if (*p == '\\' && p + 1 < end) {
					p++;
				} else if (*p == '"') {
					quoted = false;
				}
				continue;
			}
			if (*p == ';' || (*p == '#' && is_hash_comment (line, p))) {
				comment = p;
				break;
			}
			if (*p == '/' && p + 1 < end && p[1] == '*') {
				block_comment = true;
				p++;
				continue;
			}
			if (*p == '"') {
				quoted = true;
			}
			if (*p == '.' && !directive && (p == line
					|| (!isalnum ((ut8)p[-1]) && p[-1] != '_' && p[-1] != '.'))) {
				int i;
				for (i = 0; directives[i]; i++) {
					size_t len = strlen (directives[i]);
					if ((leading || !strcmp (directives[i], ".get"))
							&& (size_t)(end - p) >= len && !strncmp (p, directives[i], len)
							&& (p + len == end || isspace ((ut8)p[len]))) {
						directive = p;
						break;
					}
				}
			}
			if (!isspace ((ut8)*p)) {
				leading = false;
			}
		}
		bool ok;
		if (directive) {
			ok = r_strbuf_append_n (&sb, line, directive - line)
				&& r_strbuf_append (&sb, "<{")
				&& r_strbuf_append_n (&sb, directive + 1, comment - directive - 1)
				&& r_strbuf_append (&sb, "}>");
		} else {
			ok = r_strbuf_append_n (&sb, line, end - line);
		}
		if (!ok || (*end && !r_strbuf_append (&sb, "\n"))) {
			r_strbuf_fini (&sb);
			return NULL;
		}
		p = *end? end + 1: end;
	}
	return r_strbuf_drain_nofree (&sb);
}

R_API char *r_asm_list_directives(void) {
	RStrBuf *sb = r_strbuf_new (NULL);
	int i;
	for (i = 0; directives[i]; i++) {
		r_strbuf_appendf (sb, "%s\n", directives[i]);
	}
	return r_strbuf_drain (sb);
}

static int r_asm_assemble_single(RAsm *a, RAnalOp *op, const char *buf, bool sizing) {
	R_RETURN_VAL_IF_FAIL (a && op && buf, 0);
	r_asm_update_session (a);
	if (!a->ecur) {
		return 0;
	}
	char *b = strdup (buf);
	if (!b) {
		return 0;
	}
	r_str_case (b, false);
	op->addr = a->pc;
	r_anal_op_set_mnemonic (op, op->addr, b);
	int ret = r_arch_session_encode (a->ecur, op, sizing? R_ARCH_ENCODE_MASK_SIZING: 0)? op->size: 0;
	free (b);
	return ret;
}

R_API RAsmCode *r_asm_mdisassemble(RAsm *a, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (a && buf && len >= 0, NULL);
	r_asm_update_session (a);
	ut64 pc = a->pc;
	ut64 idx;
	int ret;
	const size_t addrbytes = a->config->addrbytes > 0? a->config->addrbytes: 1;
	int mininstrsize = 1;
	if (a->arch) {
		mininstrsize = R_MAX (1, r_arch_info (a->arch, R_ARCH_INFO_MINOP_SIZE));
	}

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
		r_asm_disassemble_do (a, &op, buf + idx, len - idx);
		ret = (op.size > 0)? op.size: mininstrsize;
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
	if (ret && p && !a->pseudo) {
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

static int parse_asm_directive(RAsm *a, RAnalOp *op, RAsmCode *acode, ut8 *fill_value, AsmCharset *charset, char *ptr_start, R_INOUT ut64 *off, bool last_stage) {
	const char *asmcpu = R_UNWRAP3 (a, config, cpu);
	int ret = -1;
	char *ptr = ptr_start;
	char *ptr2 = NULL;
	r_str_trim (ptr);
	if (r_str_startswith (ptr, ".intel_syntax")) {
		a->config->syntax = R_ARCH_SYNTAX_INTEL;
		ret = 0;
	} else if (r_str_startswith (ptr, ".att_syntax")) {
		a->config->syntax = R_ARCH_SYNTAX_ATT;
		ret = 0;
	} else if (r_str_startswith (ptr, ".endian")) {
		r_asm_set_big_endian (a, atoi (ptr + 7));
		ret = 0;
	} else if (r_str_startswith (ptr, ".big_endian")) {
		r_asm_set_big_endian (a, true);
		ret = 0;
	} else if (r_str_startswith (ptr, ".lil_endian") || r_str_startswith (ptr, "little_endian")) {
		r_asm_set_big_endian (a, false);
		ret = 0;
	} else if (asm_directive (ptr, ".charset")) {
		ret = asm_set_charset (charset, ptr + 8);
	} else if (asm_directive (ptr, ".ascii") || asm_directive (ptr, ".asciz")
			|| asm_directive (ptr, ".asciiz") || asm_directive (ptr, ".string")) {
		char *arg = ptr;
		while (*arg && !isspace ((ut8)*arg)) {
			arg++;
		}
		ret = r_asm_pseudo_string (op, charset, arg, !asm_directive (ptr, ".ascii"));
	} else if (r_str_startswith (ptr, ".extern")) {
		char *str = r_str_trim_dup (ptr + strlen (".extern"));
		if (!r_asm_code_equ_get (acode, str)) {
			// fails without the exec grain, as in the sandboxed http server
			void *p = r_lib_dl_open ("libr_core." R_LIB_EXT, false);
			void *a = p? r_lib_dl_sym (p, str): NULL;
			if (a) {
				char *val = r_str_newf ("%p", a);
				// Will be good to have a separate api for R2_590 to let the caller resolve those pointers
				r_asm_code_set_equ (acode, str, val);
				R_LOG_INFO ("Resolved symbol '%s' = %s", str, val);
				free (val);
			} else {
				R_LOG_WARN ("Cannot resolve '%s'", str);
			}
			r_lib_dl_close (p);
		}
		free (str);
		ret = 0;
	} else if (r_str_startswith (ptr, ".align") && isspace ((ut8)ptr[6])) {
		char *str = r_str_trim_dup (ptr + 6);
		ret = str? r_asm_pseudo_align (a, acode, op, str, *fill_value, last_stage): -1;
		free (str);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".fillvalue") && isspace ((ut8)ptr[10])) {
		ret = asm_parse_fill_byte (ptr + 10, ".fillvalue", fill_value)? 0: -1;
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
		const char *err = NULL;
		int bits = r_num_math_err (NULL, ptr + 6, &err);
		if (err) {
			R_LOG_ERROR ("Invalid number for .bits: %s", err);
			ret = -1;
		} else if (! (r_asm_set_bits (a, bits))) {
			R_LOG_ERROR ("Unsupported value for .bits");
			ret = -1;
		} else {
			ret = 0;
		}
	} else if (r_str_startswith (ptr, ".fill ")) {
		ret = r_asm_pseudo_fill (a, op, ptr + 6, *fill_value, last_stage);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".kernel ")) {
		r_syscall_setup (a->syscall, a->config->arch, a->config->bits, asmcpu, ptr + 8);
		ret = 0;
	} else if (r_str_startswith (ptr, ".cpu ")) {
		r_arch_config_set_cpu (a->config, ptr + 5);
		ret = 0;
	} else if (r_str_startswith (ptr, ".os ")) {
		r_syscall_setup (a->syscall, a->config->arch, a->config->bits, asmcpu, ptr + 4);
		ret = 0;
	} else if (r_str_startswith (ptr, ".hex ")) {
		ut8 *bytes = malloc ((1 + strlen (ptr + 5)) / 2);
		if (bytes) {
			int size = r_hex_str2bin (ptr + 5, bytes);
			if (size > 0) {
				ret = asm_op_set_data (op, bytes, size);
			}
			free (bytes);
		}
	} else if (r_str_startswith (ptr, ".byte ") || r_str_startswith (ptr, ".int8 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 6, 1, true, last_stage, true);
		if (ret < 0) {
			return ret;
		}
	} else if ((r_str_startswith (ptr, ".int16 ")) || r_str_startswith (ptr, ".short ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 2, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".int32 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 4, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".int64 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 8, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".db ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 4, 1, true, last_stage, true);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".word ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 6, 2, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".dw ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 4, 2, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".dword ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 4, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".dd ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 4, 4, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".qword ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 8, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".dq ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 4, 8, false, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".uint8 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 7, 1, true, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".uint16 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 8, 2, true, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".uint32 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 8, 4, true, last_stage, false);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".uint64 ")) {
		ret = r_asm_pseudo_intN (a, op, ptr + 8, 8, true, last_stage, false);
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
		ret = r_asm_pseudo_org (a, op, ptr + 5, off, last_stage);
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
			if (r_str_word_set0 (args) == 6) {
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
			RCFloatProfile fp = {
				.sign_bits = atoi (r_str_word_get0 (args, 0)),
				.exp_bits = atoi (r_str_word_get0 (args, 1)),
				.mant_bits = atoi (r_str_word_get0 (args, 2)),
				.bias = atoi (r_str_word_get0 (args, 3)),
				.big_endian = atoi (r_str_word_get0 (args, 4)),
				.explicit_leading_bit = atoi (r_str_word_get0 (args, 5))
			};
			if (!r_cfloat_profile_valid (&fp)) {
				R_LOG_ERROR ("Invalid .cfloat field sizes");
				ret = -1;
			} else {
				acode->cfloat_profile = fp;
			}
		}
		free (args);
	} else if (r_str_startswith (ptr, ".float ")) {
		const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
		acode->cfloat_profile.big_endian = be;
		ret = r_asm_pseudo_float (a, op, ptr + 7, &acode->cfloat_profile);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".double ")) {
		const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
		RCFloatProfile profile = { 1, 11, 52, 1023, be, false };
		ret = r_asm_pseudo_float (a, op, ptr + 8, &profile);
		if (ret < 0) {
			return ret;
		}
	} else if (r_str_startswith (ptr, ".bf16 ")) {
		const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
		RCFloatProfile profile = { 1, 8, 7, 127, be, false };
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


R_API RAsmCode *r_asm_assemble(RAsm *a, const char *assembly) {
	int stage, ret, idx, ctr, i, linenum = 0;
	char *ptr = NULL, *ptr_start = NULL;
	RAnalOp op = { 0 };
	ut64 off, pc;
	ut8 fill_value = 0;
	AsmCharset charset = {0};

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
	size_t bytes_size = 64;
	acode->bytes = calloc (1, bytes_size);

	char *lbuf = strdup (assembly);
	if (!lbuf || !acode->assembly || !acode->bytes) {
		goto fail;
	}
	if (a->use_spp) {
		SppProc preprocessor = *spp_default_proc ();
		preprocessor.filter = replace_directives;
		char *expanded = spp_eval_str (&preprocessor, lbuf);
		free (lbuf);
		lbuf = expanded;
		if (!lbuf) {
			free (tokens);
			r_asm_code_free (acode);
			return NULL;
		}
	}
	char *prepared = asm_prepare_source (a, lbuf);
	free (lbuf);
	lbuf = prepared;
	if (!lbuf) {
		goto fail;
	}
	bool labels = !!asm_find_unquoted (lbuf, ":");

	/* Tokenize */
	for (tokens[0] = lbuf, ctr = 0; (ptr = asm_find_unquoted (tokens[ctr], ";\n\r"));) {
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
	for (stage = 0; stage < STAGES; stage++) {
		if (stage < 2 && !labels) {
			continue;
		}
		fill_value = 0;
		r_muta_session_free (charset.encoder);
		charset.encoder = NULL;
		r_asm_set_pc (a, pc);
		linenum = 0;
		for (idx = ret = i = 0, off = a->pc; i <= ctr; i++) {
			buf_token = tokens[i];
			if (!buf_token) {
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
			r_asm_set_pc (a, a->pc + ret);
			off = a->pc;
			idx += ret;
			ret = 0;
			if (!*ptr_start) {
				continue;
			}
			linenum++;
			/* labels */
			if (labels && (ptr = asm_find_unquoted (ptr_start, ":"))) {
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
				bool literal = r_str_startswith (ptr_start, ".equ ")
					|| r_str_startswith (ptr_start, ".ascii")
					|| r_str_startswith (ptr_start, ".asciz")
					|| asm_directive (ptr_start, ".string")
					|| asm_directive (ptr_start, ".charset")
					|| r_str_startswith (ptr_start, ".incbin ");
				char *str = literal? strdup (ptr_start): r_asm_code_equ_replace (acode, ptr_start);
				if (!str) {
					goto fail;
				}
				ret = parse_asm_directive (a, &op, acode, &fill_value, &charset, str, &off, stage == STAGES - 1);
				if (ret < 0) {
					R_LOG_ERROR ("Cannot assemble '%s' at line %d", literal? ptr_start: str, linenum);
					free (str);
					goto fail;
				}
				free (str);
				if (ret == 0) {
					continue;
				}
			} else { /* Instruction */
				char *str = ptr_start;
				r_str_trim (str);
				if (!*ptr_start) {
					continue;
				}
				str = r_asm_code_equ_replace (acode, ptr_start);
				if (!str) {
					goto fail;
				}
				ret = r_asm_assemble_single (a, &op, str, stage != STAGES - 1);
				free (str);
			}
			if (ret > 0 && (ut64)ret > UT64_MAX - a->pc) {
				R_LOG_ERROR ("Assembled PC overflow at line %d", linenum);
				goto fail;
			}
			// RAsmCode.len is an int
			size_t len = 0;
			if (ret > 0 && (r_add_overflow ((size_t)idx, (size_t)ret, &len) || len > INT_MAX)) {
				R_LOG_ERROR ("Assembled code is too large at line %d", linenum);
				goto fail;
			}
			if (stage == STAGES - 1) {
				if (ret < 1) {
					R_LOG_ERROR ("Cannot assemble '%s' at line %d", ptr_start, linenum);
					goto fail;
				}
				if (!op.bytes || op.size < ret) {
					R_LOG_ERROR ("Assembled size mismatch (%d of %d bytes) at line %d", op.size, ret, linenum);
					goto fail;
				}
				if (len > bytes_size) {
					size_t new_size;
					ut8 *newbuf = r_mul_overflow (len, (size_t)2, &new_size)? NULL: realloc (acode->bytes, new_size);
					if (!newbuf) {
						goto fail;
					}
					memset (newbuf + bytes_size, 0, new_size - bytes_size);
					acode->bytes = newbuf;
					bytes_size = new_size;
				}
				memcpy (acode->bytes + idx, op.bytes, ret);
				acode->len = (int)len;
			}
		}
	}
	r_muta_session_free (charset.encoder);
	r_muta_free (charset.muta);
	free (lbuf);
	free (tokens);
	r_anal_op_fini (&op);
	return acode;
fail:
	r_muta_session_free (charset.encoder);
	r_muta_free (charset.muta);
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
		code->bytes = NULL;
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
	if (!strcmp (name, "camel")) {
		return R_ARCH_SYNTAX_CAMEL;
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
	RArchPlugin *plugin = R_UNWRAP4 (a, arch, session, plugin);
	RList *list = plugin
		? r_arch_plugin_cpus (plugin)
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
