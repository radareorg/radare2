/* radare - LGPL - Copyright 2009-2018 - pancake, nibble */

#include <stdio.h>
#include <r_core.h>
#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <spp/spp.h>
#include <config.h>

R_LIB_VERSION (r_asm);

char *directives[] = {
	".include", ".error", ".warning",
	".echo", ".if", ".ifeq", ".endif",
	".else", ".set", ".get", NULL
};

static RAsmPlugin *asm_static_plugins[] = { R_ASM_STATIC_PLUGINS };

/* pseudo.c - private api */
static int r_asm_pseudo_align(RAsmCode *acode, RAsmOp *op, char *input) {
	acode->code_align = r_num_math (NULL, input);
	return 0;
}

static int r_asm_pseudo_string(RAsmOp *op, char *input, int zero) {
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
	r_hex_bin2str ((ut8*)input, len, r_strbuf_get (&op->buf_hex));
	r_strbuf_set (&op->buf, input); // uh?
	return len;
}

static inline int r_asm_pseudo_arch(RAsm *a, char *input) {
	if (!r_asm_use (a, input)) {
		eprintf ("Error: Unknown plugin\n");
		return -1;
	}
	return 0;
}

static inline int r_asm_pseudo_bits(RAsm *a, char *input) {
	if (!(r_asm_set_bits (a, r_num_math (NULL, input)))) {
		eprintf ("Error: Unsupported bits value\n");
		return -1;
	}
	return 0;
}

static inline int r_asm_pseudo_org(RAsm *a, char *input) {
	r_asm_set_pc (a, r_num_math (NULL, input));
	return 0;
}

// wtf isnt this the same as r_asm_op_set_hex() ??
static inline int r_asm_pseudo_hex(RAsmOp *op, char *input) {
	// assume input fits inside op->buf
	int len = r_hex_str2bin (input, (ut8*)r_strbuf_get (&op->buf));
	r_asm_op_set_hex (op, r_str_trim_head_tail (input));
	if (len < 0) {
		len = -len;
		len--;
		eprintf ("Buffer truncated at %d because of the RAsmOp abuse.\nInput: %s\n", len, input);
	}
	return len;
}

static inline int r_asm_pseudo_intN(RAsm *a, RAsmOp *op, char *input, int n) {
	short s;
	int i;
	long int l;
	ut64 s64 = r_num_math (NULL, input);
	if (n != 8 && s64 >> (n * 8)) {
		eprintf ("int16 Out is out of range\n");
		return 0;
	}
	// XXX honor endian here
	ut8 *buf = (ut8*)r_strbuf_get (&op->buf);
	if (n == 2) {
		s = (short)s64;
		r_write_ble16 (buf, s, a->big_endian);
	} else if (n == 4) {
		i = (int)s64;
		r_write_ble32 (buf, i, a->big_endian);
	} else if (n == 8) {
		l = (long int)s64;
		r_write_ble64 (buf, l, a->big_endian);
	} else {
		return 0;
	}
	r_hex_bin2str (buf, n, r_strbuf_get (&op->buf_hex));
	return n;
}

static inline int r_asm_pseudo_int16(RAsm *a, RAsmOp *op, char *input) {
	return r_asm_pseudo_intN (a, op, input, 2);
}

static inline int r_asm_pseudo_int32(RAsm *a, RAsmOp *op, char *input) {
	return r_asm_pseudo_intN (a, op, input, 4);
}

static inline int r_asm_pseudo_int64(RAsm *a, RAsmOp *op, char *input) {
	return r_asm_pseudo_intN (a, op, input, 8);
}

static inline int r_asm_pseudo_byte(RAsmOp *op, char *input) {
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

static inline int r_asm_pseudo_fill(RAsmOp *op, char *input) {
	int i, repeat = 0, size=0, value=0;
	sscanf (input, "%d,%d,%d", &repeat, &size, &value); // use r_num?
	size *= (sizeof (value) * repeat);
	if (size > 0) {
		ut8 *buf = malloc (size);
		for (i = 0; i < size; i+= sizeof(value)) {
			memcpy (&buf[i], &value, sizeof(value));
		}
		r_asm_op_set_buf (op, buf, size);
		free (buf);
	} else {
		size = 0;
	}
	return size;
}

static inline int r_asm_pseudo_incbin(RAsmOp *op, char *input) {
	int bytes_read = 0;
	r_str_replace_char (input, ',', ' ');
	// int len = r_str_word_count (input);
	r_str_word_set0 (input);
	//const char *filename = r_str_word_get0 (input, 0);
	int skip = (int)r_num_math (NULL, r_str_word_get0 (input, 1));
	int count = (int)r_num_math (NULL,r_str_word_get0 (input, 2));
	char *content = r_file_slurp (input, &bytes_read);
	if (skip > 0) {
		skip = skip > bytes_read ? bytes_read : skip;
	}
	if (count > 0) {
		count = count > bytes_read ? 0 : count;
	} else {
		count = bytes_read;
	}
	// Need to handle arbitrary amount of data
	r_buf_free (op->buf_inc);
	op->buf_inc = r_buf_new_with_string (content + skip);
	// Terminate the original buffer
	free (content);
	return count;
}

static void plugin_free(RAsmPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
}

R_API RAsm *r_asm_new() {
	int i;
	RAsm *a = R_NEW0 (RAsm);
	if (!a) {
		return NULL;
	}
	a->dataalign = 1;
	a->bits = R_SYS_BITS;
	a->bitshift = 0;
	a->syntax = R_ASM_SYNTAX_INTEL;
	a->plugins = r_list_newf ((RListFree)plugin_free);
	if (!a->plugins) {
		free (a);
		return NULL;
	}
	for (i = 0; asm_static_plugins[i]; i++) {
		r_asm_add (a, asm_static_plugins[i]);
	}
	return a;
}

R_API int r_asm_setup(RAsm *a, const char *arch, int bits, int big_endian) {
	int ret = 0;
	ret |= !r_asm_use (a, arch);
	ret |= !r_asm_set_bits (a, bits);
	return ret;
}

// TODO: spagueti
R_API int r_asm_filter_input(RAsm *a, const char *f) {
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

R_API int r_asm_filter_output(RAsm *a, const char *f) {
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

R_API RAsm *r_asm_free(RAsm *a) {
	if (a) {
		if (a->cur && a->cur->fini) {
			a->cur->fini (a->cur->user);
		}
		if (a->plugins) {
			r_list_free (a->plugins);
			a->plugins = NULL;
		}
		r_syscall_free (a->syscall);
		free (a->cpu);
		sdb_free (a->pair);
		ht_free (a->flags);
		a->pair = NULL;
		free (a);
	}
	return NULL;
}

R_API void r_asm_set_user_ptr(RAsm *a, void *user) {
	a->user = user;
}

R_API bool r_asm_add(RAsm *a, RAsmPlugin *foo) {
	RListIter *iter;
	RAsmPlugin *h;
	// TODO: cache foo->name length and use memcmp instead of strcmp
	if (!foo->name) {
		return false;
	}
	if (foo->init) {
		foo->init (a->user);
	}
	r_list_foreach (a->plugins, iter, h) {
		if (!strcmp (h->name, foo->name)) {
			return false;
		}
	}
	r_list_append (a->plugins, foo);
	return true;
}

R_API int r_asm_del(RAsm *a, const char *name) {
	/* TODO: Implement r_asm_del */
	return false;
}

R_API int r_asm_is_valid(RAsm *a, const char *name) {
	RAsmPlugin *h;
	RListIter *iter;
	if (!name || !*name) {
		return false;
	}
	r_list_foreach (a->plugins, iter, h) {
		if (!strcmp (h->name, name)) {
			return true;
		}
	}
	return false;
}

R_API bool r_asm_use_assembler(RAsm *a, const char *name) {
	RAsmPlugin *h;
	RListIter *iter;
	if (a) {
		if (name && *name) {
			r_list_foreach (a->plugins, iter, h) {
				if (h->assemble && !strcmp (h->name, name)) {
					a->acur = h;
					return true;
				}
			}
		}
		a->acur = NULL;
	}
	return false;
}

// TODO: this can be optimized using r_str_hash()
R_API int r_asm_use(RAsm *a, const char *name) {
	RAsmPlugin *h;
	RListIter *iter;
	if (!a || !name) {
		return false;
	}
	r_list_foreach (a->plugins, iter, h) {
		if (!strcmp (h->name, name) && h->arch) {
			if (!a->cur || (a->cur && strcmp (a->cur->arch, h->arch))) {
				char *r2prefix = r_str_r2_prefix (R2_SDB_OPCODES);
				char *file = r_str_newf ("%s/%s.sdb", r_str_get (r2prefix), h->arch);
				r_asm_set_cpu (a, NULL);
				sdb_free (a->pair);
				a->pair = sdb_new (NULL, file, 0);
				free (r2prefix);
				free (file);
			}
			a->cur = h;
			return true;
		}
	}
	sdb_free (a->pair);
	a->pair = NULL;
	return false;
}

static int has_bits(RAsmPlugin *h, int bits) {
	return (h && h->bits && (bits & h->bits));
}

R_API void r_asm_set_cpu(RAsm *a, const char *cpu) {
	if (a) {
		free (a->cpu);
		a->cpu = cpu? strdup (cpu): NULL;
	}
}

R_API int r_asm_set_bits(RAsm *a, int bits) {
	if (has_bits (a->cur, bits)) {
		a->bits = bits; // TODO : use OR? :)
		return true;
	}
	return false;
}

R_API bool r_asm_set_big_endian(RAsm *a, bool b) {
	if (!a || !a->cur) {
		return false;
	}
	a->big_endian = false; //little endian by default
	switch (a->cur->endian) {
	case R_SYS_ENDIAN_NONE:
	case R_SYS_ENDIAN_BI:
		// let user select
		a->big_endian = b;
		break;
	case R_SYS_ENDIAN_LITTLE:
		a->big_endian = false;
		break;
	case R_SYS_ENDIAN_BIG:
		a->big_endian = true;
		break;
	default:
		eprintf ("RAsmPlugin doesn't specify endianness\n");
		break;
	}
	return a->big_endian;
}

R_API int r_asm_set_syntax(RAsm *a, int syntax) {
	switch (syntax) {
	case R_ASM_SYNTAX_REGNUM:
	case R_ASM_SYNTAX_INTEL:
	case R_ASM_SYNTAX_MASM:
	case R_ASM_SYNTAX_ATT:
	case R_ASM_SYNTAX_JZ:
		a->syntax = syntax;
		return true;
	default:
		return false;
	}
}

R_API int r_asm_set_pc(RAsm *a, ut64 pc) {
	a->pc = pc;
	return true;
}

static bool isInvalid (RAsmOp *op) {
	const char *buf_asm = r_strbuf_get (&op->buf_asm);
	return (buf_asm && *buf_asm && !strcmp (buf_asm, "invalid"));
}

R_API int r_asm_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int ret;
	if (!a || !buf || !op) {
		return -1;
	}
	if (len < 1) {
		return 0;
	}
	ret = op->payload = 0;
	op->size = 4;
	op->bitsize = 0;
	r_asm_op_set_asm (op, "");
	if (a->pcalign) {
		const int mod = a->pc % a->pcalign;
		if (mod) {
			op->size = a->pcalign - mod;
			r_strbuf_set (&op->buf_asm, "unaligned");
			r_strbuf_set (&op->buf_hex, "");
			// assume op->size after pcalign-mod will be small enough to not need checks here
			r_hex_bin2str (buf, op->size, r_strbuf_get (&op->buf_hex));
			return -1;
		}
	}
	if (a->cur && a->cur->disassemble) {
		// shift buf N bits
		if (a->bitshift > 0) {
			ut8 *tmp = calloc (len, 1);
			if (tmp) {
				r_mem_copybits_delta (tmp, 0, buf, a->bitshift, (len * 8) - a->bitshift);
				ret = a->cur->disassemble (a, op, tmp, len);
				free (tmp);
			}
		} else {
			ret = a->cur->disassemble (a, op, buf, len);
		}
	}
	if (ret < 0) {
		ret = 0;
	}
	int oplen = r_asm_op_get_size (op);
	if (op->bitsize > 0) {
		oplen = op->size = op->bitsize / 8;
		a->bitshift += op->bitsize % 8;
		int count = a->bitshift / 8;
		if (count > 0) {
			oplen = op->size = op->size + count;
			a->bitshift %= 8;
		}
	} else {
		oplen = op->size;
	}
	if (oplen < 1) {
		oplen = 1;
	}

	if (op->size < 1 || isInvalid (op)) {
		if (a->invhex) {
			if (a->bits == 16) {
				ut16 b = r_read_le16 (buf);
				r_strbuf_set (&op->buf_asm, sdb_fmt (".word 0x%04x", b));
			} else {
				ut32 b = r_read_le32 (buf);
				r_strbuf_set (&op->buf_asm, sdb_fmt (".dword 0x%08x", b));
			}
			// TODO: something for 64bits too?
		} else {
			r_strbuf_set (&op->buf_asm, "invalid");
		}
	}
	if (a->ofilter) {
		char *buf_asm = r_strbuf_get (&op->buf_asm);
		r_parse_parse (a->ofilter, buf_asm, buf_asm);
	}
	int opsz = (op->size > 0)? R_MAX (0, R_MIN (len, op->size)): 1;
	r_asm_op_set_buf (op, buf, opsz);
	return ret;
}

typedef int (*Ase)(RAsm *a, RAsmOp *op, const char *buf);

static bool assemblerMatches(RAsm *a, RAsmPlugin *h) {
	if (!a || !h->arch || !h->assemble || !has_bits (h, a->bits)) {
		return false;
	}
	return (!strncmp (a->cur->arch, h->arch, strlen (a->cur->arch)));
}

static Ase findAssembler(RAsm *a, const char *kw) {
	Ase ase = NULL;
	RAsmPlugin *h;
	RListIter *iter;
	if (a->acur && a->acur->assemble) {
		return a->acur->assemble;
	}
	r_list_foreach (a->plugins, iter, h) {
		if (assemblerMatches (a, h)) {
			if (kw) {
				if (strstr (h->name, kw)) {
					return h->assemble;
				}
			} else {
				ase = h->assemble;
			}
		}
	}
	return ase;
}

static char *replace_directives_for(char *str, char *token) {
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
				*nl ++ = 0;
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
	char *dir = directives[i++];
	char *o = replace_directives_for (str, dir);
	while (dir) {
		o = replace_directives_for (o, dir);
		dir = directives[i++];
	}
	return o;
}

R_API void r_asm_list_directives() {
	int i = 0;
	char *dir = directives[i++];
	while (dir) {
		printf ("%s\n", dir);
		dir = directives[i++];
	}
}

R_API int r_asm_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int ret = 0;
	char *b = strdup (buf);
	if (!b) {
		return 0;
	}
	if (a->ifilter) {
		r_parse_parse (a->ifilter, buf, b);
	}
	r_str_case (b, 0); // to-lower
	memset (op, 0, sizeof (RAsmOp));
	if (a->cur) {
		Ase ase = NULL;
		if (!a->cur->assemble) {
			/* find callback if no assembler support in current plugin */
			ase = findAssembler (a, ".ks");
			if (!ase) {
				ase = findAssembler (a, ".nz");
				if (!ase) {
					ase = findAssembler (a, NULL);
				}
			}
		} else {
			ase = a->cur->assemble;
		}
		if (ase) {
			ret = ase (a, op, b);
		}
	}
	// XXX delete this block, the ase thing should be setting asm, buf and hex
	if (op && ret > 0) {
		op->size = ret; // XXX shouldnt be necessary
		r_asm_op_set_asm (op, b); // XXX ase should be updating this already, isnt?
		ut8 *ophex = (ut8*)r_strbuf_get (&op->buf_hex);
		if (!*ophex) {
			ut8 *opbuf = (ut8*)r_strbuf_get (&op->buf);
			r_asm_op_set_buf (op, opbuf, ret);
		}
	}
	free (b);
	return ret;
}

// TODO: Use RStrBuf api here pls
R_API RAsmCode* r_asm_mdisassemble(RAsm *a, const ut8 *buf, int len) {
	RStrBuf *buf_asm;
	RAsmCode *acode;
	ut64 pc = a->pc;
	RAsmOp op;
	ut64 idx;
	int ret, slen;
	const int addrbytes = a->user ? ((RCore *)a->user)->io->addrbytes : 1;

	if (!(acode = r_asm_code_new ())) {
		return NULL;
	}
	if (!(acode->buf = malloc (1 + len))) {
		return r_asm_code_free (acode);
	}
	memcpy (acode->buf, buf, len);
	if (!(acode->buf_hex = calloc (2, len + 1))) {
		return r_asm_code_free (acode);
	}
	r_hex_bin2str (buf, len, acode->buf_hex);
	if (!(buf_asm = r_strbuf_new (NULL))) {
		return r_asm_code_free (acode);
	}
	for (idx = ret = slen = 0; idx + addrbytes <= len; idx += addrbytes * ret) {
		r_asm_set_pc (a, pc + idx);
		ret = r_asm_disassemble (a, &op, buf + idx, len - idx);
		if (ret < 1) {
			ret = 1;
		}
		if (a->ofilter) {
			char *op_buf_asm = r_strbuf_get (&op.buf_asm);
			r_parse_parse (a->ofilter, op_buf_asm, op_buf_asm);
		}
		r_strbuf_append (buf_asm, r_strbuf_get (&op.buf_asm));
		r_strbuf_append (buf_asm, "\n");
	}
	acode->buf_asm = r_strbuf_drain (buf_asm);
	acode->len = idx;
	return acode;
}

R_API RAsmCode* r_asm_mdisassemble_hexstr(RAsm *a, const char *hexstr) {
	RAsmCode *ret;
	ut8 *buf;
	int len;
	if (!(buf = malloc (strlen (hexstr) + 1))) {
		return NULL;
	}
	len = r_hex_str2bin (hexstr, buf);
	if (len < 1) {
		free (buf);
		return NULL;
	}
	ret = r_asm_mdisassemble (a, buf, (ut64)len);
	if (ret && a->ofilter) {
		r_parse_parse (a->ofilter, ret->buf_asm, ret->buf_asm);
	}
	free (buf);
	return ret;
}

R_API RAsmCode* r_asm_assemble_file(RAsm *a, const char *file) {
	RAsmCode *ac = NULL;
	char *f = r_file_slurp (file, NULL);
	if (f) {
		ac = r_asm_massemble (a, f);
		free (f);
	}
	return ac;
}

static void flag_free_kv(HtKv *kv) {
	free (kv->key);
	free (kv->value);
}

static void *dup_val(const void *v) {
	return (void *)strdup ((char *)v);
}

R_API RAsmCode *r_asm_massemble(RAsm *a, const char *buf) {
	int labels = 0, num, stage, ret, idx, ctr, i, j, linenum = 0;
	char *lbuf = NULL, *ptr2, *ptr = NULL, *ptr_start = NULL;
	char *tokens[R_ASM_BUFSIZE], buf_token[R_ASM_BUFSIZE];
	const char *asmcpu = NULL;
	RAsmCode *acode = NULL;
	RAsmOp op = {0};
	ut64 off, pc;
	if (!buf) {
		return NULL;
	}
	ht_free (a->flags);
	if (!(a->flags = ht_new (dup_val, flag_free_kv, NULL))) {
		return NULL;
	}
	if (!(acode = r_asm_code_new ())) {
		return NULL;
	}
	if (!(acode->buf_asm = malloc (strlen (buf) + 16))) {
		return r_asm_code_free (acode);
	}
	strncpy (acode->buf_asm, buf, sizeof (acode->buf_asm) - 1);
	if (!(acode->buf_hex = malloc (64))) { // WTF unefficient
		return r_asm_code_free (acode);
	}
	*acode->buf_hex = 0;
	if (!(acode->buf = calloc (1, 64))) {
		return r_asm_code_free (acode);
	}
	lbuf = strdup (buf);
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
	// XXX: ops like mov eax, $pc+33 fail coz '+' is nov alid number!!!
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
	if (strchr (lbuf, ':')) {
		labels = 1;
	}
	/* Tokenize */
	for (tokens[0] = lbuf, ctr = 0;
			ctr < R_ASM_BUFSIZE - 1 &&
			((ptr = strchr (tokens[ctr], ';')) ||
			(ptr = strchr (tokens[ctr], '\n')) ||
			(ptr = strchr (tokens[ctr], '\r')));
			tokens[++ctr] = ptr + 1) {
		*ptr = '\0';
	}

#define isavrseparator(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r'||(x)==' '|| \
		(x)==','||(x)==';'||(x)=='['||(x)==']'|| \
		(x)=='('||(x)==')'||(x)=='{'||(x)=='}')

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
		for (idx = ret = i = j = 0, off = a->pc, acode->buf_hex[0] = '\0';
				i <= ctr; i++, idx += ret) {
			strncpy (buf_token, tokens[i], R_ASM_BUFSIZE - 1);
			if (inComment) {
				if (!strncmp (ptr_start, "*/", 2)) {
					inComment = false;
				}
				continue;
			}
			// XXX TODO remove arch-specific hacks
			if (!strncmp (a->cur->arch, "avr", 3)) {
				for (ptr_start = buf_token; *ptr_start &&
							    isavrseparator (*ptr_start);
					ptr_start++) {
					;
				}
			} else {
				for (ptr_start = buf_token; *ptr_start &&
							    IS_SEPARATOR (*ptr_start);
					ptr_start++) {
					;
				}
			}
			if (!strncmp (ptr_start, "/*", 2)) {
				if (!strstr (ptr_start + 2, "*/")) {
					inComment = true;
				}
				continue;
			}
			ptr = strchr (ptr_start, '#'); /* Comments */
			if (ptr && !R_BETWEEN ('0', ptr[1], '9') && ptr[1]!='-') {
				*ptr = '\0';
			}
			r_asm_set_pc (a, a->pc + ret);
			off = a->pc;
			ret = 0;
			if (!*ptr_start) {
				continue;
			}
			linenum ++;
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
					if (ptr_start[1] != 0 && ptr_start[1] != ' ') {
						*ptr = 0;
						if (acode->code_align) {
							off += (acode->code_align - (off % acode->code_align));
						}
						char food[64];
						snprintf (food, sizeof (food), "0x%"PFMT64x, off);
						ht_insert (a->flags, ptr_start, food);
						// TODO: warning when redefined
						r_asm_code_set_equ (acode, ptr_start, food);
					}
					//}
					ptr_start = ptr + 1;
				}
				ptr = ptr_start;
			}
			if (*ptr_start == '\0') {
				ret = 0;
				continue;
			}
			if (*ptr_start == '.') { /* pseudo */
				/* TODO: move into a separate function */
				ptr = ptr_start;
				if (!strncmp (ptr, ".intel_syntax", 13)) {
					a->syntax = R_ASM_SYNTAX_INTEL;
				} else if (!strncmp (ptr, ".att_syntax", 11)) {
					a->syntax = R_ASM_SYNTAX_ATT;
				} else if (!strncmp (ptr, ".endian", 7)) {
					r_asm_set_big_endian (a, atoi (ptr + 7));
				} else if (!strncmp (ptr, ".big_endian", 7 + 4)) {
					r_asm_set_big_endian (a, true);
				} else if (!strncmp (ptr, ".lil_endian", 7 + 4) || !strncmp (ptr, "little_endian", 7 + 6)) {
					r_asm_set_big_endian (a, false);
				} else if (!strncmp (ptr, ".asciz", 6)) {
					r_str_trim (ptr + 8);
					ret = r_asm_pseudo_string (&op, ptr + 8, 1);
				} else if (!strncmp (ptr, ".string ", 8)) {
					r_str_trim (ptr + 8);
					ret = r_asm_pseudo_string (&op, ptr + 8, 1);
				} else if (!strncmp (ptr, ".ascii", 6)) {
					ret = r_asm_pseudo_string (&op, ptr + 7, 0);
				} else if (!strncmp (ptr, ".align", 6)) {
					ret = r_asm_pseudo_align (acode, &op, ptr + 7);
				} else if (!strncmp (ptr, ".arm", 4)) {
					r_asm_use (a, "arm");
					r_asm_set_bits (a, 32);
					ret = 0;
				} else if (!strncmp (ptr, ".thumb", 6)) {
					r_asm_use (a, "arm");
					r_asm_set_bits (a, 16);
					ret = 0;
				} else if (!strncmp (ptr, ".arch ", 6)) {
					ret = r_asm_pseudo_arch (a, ptr+6);
				} else if (!strncmp (ptr, ".bits ", 6)) {
					ret = r_asm_pseudo_bits (a, ptr+6);
				} else if (!strncmp (ptr, ".fill ", 6)) {
					ret = r_asm_pseudo_fill (&op, ptr+6);
				} else if (!strncmp (ptr, ".kernel ", 8)) {
					r_syscall_setup (a->syscall, a->cur->arch, a->bits, asmcpu, ptr + 8);
				} else if (!strncmp (ptr, ".cpu ", 5)) {
					r_asm_set_cpu (a, ptr + 5);
				} else if (!strncmp (ptr, ".os ", 4)) {
					r_syscall_setup (a->syscall, a->cur->arch, a->bits, asmcpu, ptr + 4);
				} else if (!strncmp (ptr, ".hex ", 5)) {
					ret = r_asm_pseudo_hex (&op, ptr + 5);
				} else if ((!strncmp (ptr, ".int16 ", 7)) || !strncmp (ptr, ".short ", 7)) {
					ret = r_asm_pseudo_int16 (a, &op, ptr+7);
				} else if (!strncmp (ptr, ".int32 ", 7)) {
					ret = r_asm_pseudo_int32 (a, &op, ptr+7);
				} else if (!strncmp (ptr, ".int64 ", 7)) {
					ret = r_asm_pseudo_int64 (a, &op, ptr+7);
				} else if (!strncmp (ptr, ".size", 5)) {
					ret = true; // do nothing, ignored
				} else if (!strncmp (ptr, ".section", 8)) {
					ret = true; // do nothing, ignored
				} else if ((!strncmp (ptr, ".byte ", 6)) || (!strncmp (ptr, ".int8 ", 6))) {
					ret = r_asm_pseudo_byte (&op, ptr+6);
				} else if (!strncmp (ptr, ".glob", 5)) { // .global .globl
									 //	eprintf (".global directive not yet implemented\n");
					ret = 0;
					continue;
				} else if (!strncmp (ptr, ".equ ", 5)) {
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
					} else {
						eprintf ("Invalid syntax for '.equ': Use '.equ <word> <word>'\n");
					}
				} else if (!strncmp (ptr, ".org ", 5)) {
					ret = r_asm_pseudo_org (a, ptr+5);
					off = a->pc;
				} else if (!strncmp (ptr, ".text", 5)) {
					acode->code_offset = a->pc;
				} else if (!strncmp (ptr, ".data", 5)) {
					acode->data_offset = a->pc;
				} else if (!strncmp (ptr, ".incbin", 7)) {
					if (ptr[7] != ' ') {
						eprintf ("incbin missing filename\n");
						continue;
					}
					ret = r_asm_pseudo_incbin (&op, ptr + 8);
				} else {
					eprintf ("Unknown directive (%s)\n", ptr);
					free(lbuf);
					return r_asm_code_free (acode);
				}
				if (!ret) {
					continue;
				}
				if (ret < 0) {
					eprintf ("!!! Oops (%s)\n", ptr);
					free (lbuf);
					return r_asm_code_free (acode);
				}
			} else { /* Instruction */
				char *str = ptr_start;
				ptr_start = r_str_trim (str);
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
					eprintf ("Cannot assemble '%s' at line %d\n", ptr_start, linenum);
					free (lbuf);
					return r_asm_code_free (acode);
				}
				acode->len = idx + ret;
				char *newbuf = realloc (acode->buf, (idx + ret) * 2);
				if (!newbuf) {
					free (lbuf);
					return r_asm_code_free (acode);
				}
				acode->buf = (ut8*)newbuf;

				int newlen = strlen (acode->buf_hex) + r_strbuf_length (&op.buf_hex)
					+ r_buf_size (op.buf_inc) + 128;
				newbuf = realloc (acode->buf_hex, newlen);
				if (!newbuf) {
					free (lbuf);
					return r_asm_code_free (acode);
				}
				acode->buf_hex = newbuf;
				acode->buf = malloc (4095);
				memcpy (acode->buf + idx, r_strbuf_get (&op.buf), r_strbuf_length (&op.buf)); // ret);
				// XXX slow. use strbuf pls
				strcat (acode->buf_hex, r_strbuf_get (&op.buf_hex));
				if (r_buf_size (op.buf_inc) > 1) {
					if (*acode->buf_hex) {
						strcat (acode->buf_hex, "\n");
					}
					char *s = r_buf_free_to_string (op.buf_inc);
					if (s) {
						strcat (acode->buf_hex, s);
						free (s);
					}
				}

			}
		}
	}
	free (lbuf);
	r_hex_str2bin (acode->buf_hex, acode->buf);
	return acode;
}

R_API bool r_asm_modify(RAsm *a, ut8 *buf, int field, ut64 val) {
	return (a->cur && a->cur->modify) ? a->cur->modify (a, buf, field, val): false;
}

R_API int r_asm_get_offset(RAsm *a, int type, int idx) { // link to rbin
	if (a && a->binb.bin && a->binb.get_offset) {
		return a->binb.get_offset (a->binb.bin, type, idx);
	}
	return -1;
}

R_API char *r_asm_describe(RAsm *a, const char* str) {
	return (a && a->pair)? sdb_get (a->pair, str, 0): NULL;
}

R_API RList* r_asm_get_plugins(RAsm *a) {
	return a->plugins;
}

R_API bool r_asm_set_arch(RAsm *a, const char *name, int bits) {
	return r_asm_use (a, name)? r_asm_set_bits (a, bits): false;
}

/* to ease the use of the native bindings (not used in r2) */
R_API char *r_asm_to_string(RAsm *a, ut64 addr, const ut8 *b, int l) {
	r_asm_set_pc (a, addr);
	RAsmCode *code = r_asm_mdisassemble (a, b, l);
	if (code) {
		char *buf_asm = code->buf_asm;
		code->buf_asm = NULL;
		r_asm_code_free (code);
		return buf_asm;
	}
	return NULL;
}

R_API ut8 *r_asm_from_string(RAsm *a, ut64 addr, const char *b, int *l) {
	r_asm_set_pc (a, addr);
	RAsmCode *code = r_asm_massemble (a, b);
	if (code) {
		ut8 *buf = code->buf;
		if (l) {
			*l = code->len;
		}
		r_asm_code_free (code);
		return buf;
	}
	return NULL;
}

R_API int r_asm_syntax_from_string(const char *name) {
	if (!strcmp (name, "regnum")) {
		return R_ASM_SYNTAX_REGNUM;
	}
	if (!strcmp (name, "jz")) {
		return R_ASM_SYNTAX_JZ;
	}
	if (!strcmp (name, "intel")) {
		return R_ASM_SYNTAX_INTEL;
	}
	if (!strcmp (name, "masm")) {
		return R_ASM_SYNTAX_MASM;
	}
	if (!strcmp (name, "att")) {
		return R_ASM_SYNTAX_ATT;
	}
	return -1;
}

R_API char *r_asm_mnemonics(RAsm *a, int id, bool json) {
	if (a && a->cur && a->cur->mnemonics) {
		return a->cur->mnemonics (a, id, json);
	}
	return NULL;
}

R_API int r_asm_mnemonics_byname(RAsm *a, const char *name) {
	if (a && a->cur && a->cur->mnemonics) {
		int i;
		for (i = 0; i < 1024; i++) {
			char *n = a->cur->mnemonics (a, i, false);
			if (n && !strcmp (n, name)) {
				return i;
			}
			free (n);
		}
	}
	return 0;
}

R_API RAsmCode* r_asm_rasm_assemble(RAsm *a, const char *buf, bool use_spp) {
	char *lbuf = strdup (buf);
	if (!lbuf) {
		return NULL;
	}
	RAsmCode *acode;
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
	acode = r_asm_massemble (a, lbuf);
	free (lbuf);
	return acode;
}
