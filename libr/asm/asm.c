/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <list.h>
#include "../config.h"

R_LIB_VERSION (r_asm);

static RAsmPlugin *asm_static_plugins[] = { R_ASM_STATIC_PLUGINS };

static int r_asm_pseudo_align(RAsmOp *op, char *input) {
	eprintf ("TODO: .align\n"); // Must add padding for labels and others.. but this is from RAsm, not RAsmOp
	return 0;
}

static int r_asm_pseudo_string(RAsmOp *op, char *input, int zero) {
	int len = strlen (input)-1;
	if (len<1) return 0;
	// TODO: if not starting with '"'.. give up
	if (input[len]=='"')
		input[len] = 0;
	if (*input=='"')
		input++;
	len = r_str_unescape (input)+zero;
	r_hex_bin2str ((ut8*)input, len, op->buf_hex);
	strncpy ((char*)op->buf, input, R_ASM_BUFSIZE-1);
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

static inline int r_asm_pseudo_hex(RAsmOp *op, char *input) {
	int len = r_hex_str2bin (input, op->buf);
	strncpy (op->buf_hex, r_str_trim (input), R_ASM_BUFSIZE-1);
	return len;
}

static inline int r_asm_pseudo_intN(RAsm *a, RAsmOp *op, char *input, int n) {
	const ut8 *p;
	short s;
	int i;
	long int l;
	ut64 s64 = r_num_math (NULL, input);
	if (n!=8 && s64>>(n*8)) {
		eprintf ("int16 Out is out of range\n");
		return 0;
	}
	if (n == 2) {
		s = (short)s64;
		p = (const ut8*)&s;
	} else if (n == 4) {
		i = (int)s64;
		p = (const ut8*)&i;
	} else if (n == 8) {
		l = (long int)s64;
		p = (const ut8*)&l;
	} else return 0;
	r_mem_copyendian (op->buf, p, n, !a->big_endian);
	r_hex_bin2str (op->buf, n, op->buf_hex);
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
	for (i=0; i<len; i++) {
		const char *word = r_str_word_get0 (input, i);
		int num = (int)r_num_math (NULL, word);
		op->buf[i] = num;
	}
	r_hex_bin2str (op->buf, len, op->buf_hex);
	return len;
}

static inline int r_asm_pseudo_fill(RAsmOp *op, char *input) {
	int i, repeat=0, size=0, value=0;
	sscanf (input, "%d,%d,%d", &repeat, &size, &value); // use r_num?
	size *= repeat;
	if (size>0) {
		for (i=0; i<size; i++)
			op->buf[i] = value;
		r_hex_bin2str (op->buf, size, op->buf_hex);
	} else size = 0;
	return size;
}

R_API RAsm *r_asm_new() {
	int i;
	RAsmPlugin *static_plugin;
	RAsm *a = R_NEW (RAsm);
	if (!a) return NULL;
	a->pair = NULL;
	a->num = NULL;
	a->user = NULL;
	a->cur = NULL;
	a->binb.bin = NULL;
	a->bits = 32;
	a->cpu = NULL;
	a->big_endian = 0;
	a->pc = 0;
	a->ifilter = NULL;
	a->ofilter = NULL;
	a->syntax = R_ASM_SYNTAX_INTEL;
	a->syscall = NULL;
	a->plugins = r_list_new ();
	a->plugins->free = free;
	for (i=0; asm_static_plugins[i]; i++) {
		static_plugin = R_NEW (RAsmPlugin);
		// memleak here
		memcpy (static_plugin, asm_static_plugins[i], sizeof (RAsmPlugin));
		r_asm_add (a, static_plugin);
	}
	return a;
}

R_API int r_asm_setup(RAsm *a, const char *arch, int bits, int big_endian) {
	int ret = 0;
	ret |= !r_asm_use (a, arch);
	ret |= !r_asm_set_bits (a, bits);
	ret |= !r_asm_set_big_endian (a, big_endian);
	return ret;
}

// TODO: spagueti
R_API int r_asm_filter_input(RAsm *a, const char *f) {
	if (!a->ifilter)
		a->ifilter = r_parse_new ();
	if (!r_parse_use (a->ifilter, f)) {
		r_parse_free (a->ifilter);
		a->ifilter = NULL;
		return R_FALSE;
	}
	return R_TRUE;
}

R_API int r_asm_filter_output(RAsm *a, const char *f) {
	if (!a->ofilter)
		a->ofilter = r_parse_new ();
	if (!r_parse_use (a->ofilter, f)) {
		r_parse_free (a->ofilter);
		a->ofilter = NULL;
		return R_FALSE;
	}
	return R_TRUE;
}

R_API RAsm *r_asm_free(RAsm *a) {
	if (a) {
		if (a->cur && a->cur->fini) {
			a->cur->fini (a->cur->user);
		}
		if (a->plugins) {
			a->plugins->free = NULL;
			r_list_free (a->plugins);
			a->plugins = NULL;
		}
		free (a->cpu);
		// TODO: any memory leak here?
		sdb_free (a->pair);
		a->pair = NULL;
		// XXX: segfault, plugins cannot be freed
		free (a);
	}
	return NULL;
}

R_API void r_asm_set_user_ptr(RAsm *a, void *user) {
	a->user = user;
}

R_API int r_asm_add(RAsm *a, RAsmPlugin *foo) {
	RListIter *iter;
	RAsmPlugin *h;
	// TODO: cache foo->name length and use memcmp instead of strcmp
	if (!foo->name)
		return R_FALSE;
	if (foo->init)
		foo->init (a->user);
	r_list_foreach (a->plugins, iter, h)
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	r_list_append (a->plugins, foo);
	return R_TRUE;
}

R_API int r_asm_del(RAsm *a, const char *name) {
	/* TODO: Implement r_asm_del */
	return R_FALSE;
}


R_API int r_asm_is_valid(RAsm *a, const char *name) {
	RAsmPlugin *h;
	RListIter *iter;
	r_list_foreach (a->plugins, iter, h) {
		if (!strcmp (h->name, name))
			return R_TRUE;
	}
	return R_FALSE;
}

// TODO: this can be optimized using r_str_hash()
R_API int r_asm_use(RAsm *a, const char *name) {
	char file[1024];
	RAsmPlugin *h;
	RListIter *iter;
	r_list_foreach (a->plugins, iter, h)
		if (!strcmp (h->name, name)) {
			if (!a->cur || (a->cur && strcmp (a->cur->arch, h->arch))) {
				//const char *dop = r_config_get (core->config, "dir.opcodes");
				// TODO: allow configurable path for sdb files
				snprintf (file, sizeof (file), R_ASM_OPCODES_PATH"/%s.sdb", h->arch);
				sdb_free (a->pair);
				a->pair = sdb_new (NULL, file, 0);
			}
			a->cur = h;
			return R_TRUE;
		}
	sdb_free (a->pair);
	a->pair = NULL;
	return R_FALSE;
}

R_API int r_asm_set_subarch(RAsm *a, const char *name) {
	int ret = R_FALSE;
	if (a->cur && a->cur->set_subarch)
		ret = a->cur->set_subarch(a, name);
	return ret;
}

static int has_bits(RAsmPlugin *h, int bits) {
	if (h && h->bits && (bits & h->bits))
		return R_TRUE;
	return R_FALSE;
}

R_API void r_asm_set_cpu(RAsm *a, const char *cpu) {
	free (a->cpu);
	a->cpu = cpu? strdup (cpu): NULL;
}

R_API int r_asm_set_bits(RAsm *a, int bits) {
	if (has_bits (a->cur, bits)) {
		a->bits = bits; // TODO : use OR? :)
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_asm_set_big_endian(RAsm *a, int b) {
	a->big_endian = b;
	return R_TRUE;
}

R_API int r_asm_set_syntax(RAsm *a, int syntax) {
	switch (syntax) {
	case R_ASM_SYNTAX_REGNUM:
	case R_ASM_SYNTAX_INTEL:
	case R_ASM_SYNTAX_ATT:
		a->syntax = syntax;
		return R_TRUE;
	default:
		return R_FALSE;
	}
}

R_API int r_asm_set_pc(RAsm *a, ut64 pc) {
	a->pc = pc;
	return R_TRUE;
}

R_API int r_asm_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int oplen, ret = op->payload = 0;
	op->size = 4;
	if (len<1)
		return 0;
	// on mips/arm/sparc .. use word size
	sprintf (op->buf_asm,".byte 0x%02x %d", buf[0], len);
	if (a->cur && a->cur->disassemble)
		ret = a->cur->disassemble (a, op, buf, len);
	oplen = r_asm_op_get_size (op);
	oplen = op->size;
	if (oplen>len) oplen = len;
	if (oplen<1) oplen = 1;
	if (ret > 0) {
		if (a->ofilter)
			r_parse_parse (a->ofilter, op->buf_asm, op->buf_asm);
	//	r_hex_bin2str (buf, oplen, op->buf_hex);
	} else ret = 0;
	r_mem_copyendian (op->buf, buf, oplen, !a->big_endian);
	*op->buf_hex = 0;
	if ((oplen*4)>=sizeof(op->buf_hex))
		oplen = (sizeof(op->buf_hex)/4)-1;
	r_hex_bin2str (buf, oplen, op->buf_hex);
	return ret;
}

R_API int r_asm_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int ret = 0;
	RAsmPlugin *h;
	RListIter *iter;
	char *b = strdup (buf);
	if (a->ifilter)
		r_parse_parse (a->ifilter, buf, b);
	r_str_case (b, 0); // to-lower
	memset (op, 0, sizeof (RAsmOp));
	if (a->cur) {
		if (!a->cur->assemble) {
			/* find callback if no assembler support in current plugin */
			r_list_foreach (a->plugins, iter, h) {
				if (h->arch && h->assemble
				&& has_bits (h, a->bits)
				&& !strcmp (a->cur->arch, h->arch)) {
					ret = h->assemble (a, op, b);
					break;
				}
			}
		} else ret = a->cur->assemble (a, op, b);
	}
	if (op && ret > 0) {
		r_hex_bin2str (op->buf, ret, op->buf_hex);
		op->size = ret;
		op->buf_hex[ret*2] = 0;
		strncpy (op->buf_asm, b, R_ASM_BUFSIZE-1);
	}
	free (b);
	return ret;
}

R_API RAsmCode* r_asm_mdisassemble(RAsm *a, const ut8 *buf, int len) {
	RAsmCode *acode;
	int ret, slen;
	RAsmOp op;
	ut64 idx;

	if (!(acode = r_asm_code_new ()))
		return NULL;
	if (!(acode->buf = malloc (1+len)))
		return r_asm_code_free (acode);
	memcpy (acode->buf, buf, len);
	if (!(acode->buf_hex = malloc (2*len+1)))
		return r_asm_code_free (acode);
	r_hex_bin2str (buf, len, acode->buf_hex);
	if (!(acode->buf_asm = malloc (4)))
		return r_asm_code_free (acode);

	for (idx = ret = slen = 0, acode->buf_asm[0] = '\0'; idx < len; idx+=ret) {
		r_asm_set_pc (a, a->pc + ret);
		ret = r_asm_disassemble (a, &op, buf+idx, len-idx);
		if (ret<1) {
			eprintf ("disassemble error at offset %"PFMT64d"\n", idx);
ret = 1;
//			return acode;
		}
		if (a->ofilter)
			r_parse_parse (a->ofilter, op.buf_asm, op.buf_asm);
		slen += strlen (op.buf_asm) + 2;
		if (!(acode->buf_asm = realloc (acode->buf_asm, slen)))
			return r_asm_code_free (acode);
		strcat (acode->buf_asm, op.buf_asm);
		strcat (acode->buf_asm, "\n");
	}
	acode->len = idx;
	return acode;
}

R_API RAsmCode* r_asm_mdisassemble_hexstr(RAsm *a, const char *hexstr) {
	RAsmCode *ret;
	ut8 *buf;
	int len;

	if (!(buf = malloc (1+strlen (hexstr))))
		return NULL;
	len = r_hex_str2bin (hexstr, buf);
	if (len == -1) {
		free (buf);
		return NULL;
	}
	ret = r_asm_mdisassemble (a, buf, (ut64)len);
	if (ret && a->ofilter)
		r_parse_parse (a->ofilter, ret->buf_asm, ret->buf_asm);
	free (buf);
	return ret;
}

R_API RAsmCode* r_asm_assemble_file(RAsm *a, const char *file) {
	RAsmCode *ac;
	char *f = r_file_slurp (file, NULL);
	if (!f) return NULL;
	ac = r_asm_massemble (a, f);
	free (f);
	return ac;
}

R_API RAsmCode* r_asm_massemble(RAsm *a, const char *buf) {
	int labels = 0, num, stage, ret, idx, ctr, i, j, linenum = 0;
	char *lbuf = NULL, *ptr2, *ptr = NULL, *ptr_start = NULL,
		 *tokens[R_ASM_BUFSIZE], buf_token[R_ASM_BUFSIZE];
	RAsmCode *acode = NULL;
	RAsmOp op;
	ut64 off, pc;
	if (buf == NULL)
		return NULL;
	if (!(acode = r_asm_code_new ()))
		return NULL;
	if (!(acode->buf_asm = malloc (strlen (buf)+16)))
		return r_asm_code_free (acode);
	strncpy (acode->buf_asm, buf, sizeof (acode->buf_asm)-1);
	if (!(acode->buf_hex = malloc (64))) // WTF unefficient
		return r_asm_code_free (acode);
	*acode->buf_hex = 0;
	if (!(acode->buf = malloc (64)))
		return r_asm_code_free (acode);
	lbuf = strdup (buf);
	memset (&op, 0, sizeof (op));

	/* accept ';' as comments when input is multiline */
	{
		char *nl = strchr (lbuf, '\n');
		if (nl) {
			if (strchr (nl+1, '\n'))
				r_str_replace_char (lbuf, ';', '#');
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
			p = strstr (p+5, "$sys.");
		}
	}

	if (strchr (lbuf, ':'))
		labels = 1;

	/* Tokenize */
	for (tokens[0] = lbuf, ctr = 0;
		ctr < R_ASM_BUFSIZE - 1 &&
		((ptr = strchr (tokens[ctr], ';')) ||
		(ptr = strchr (tokens[ctr], '\n')) ||
		(ptr = strchr (tokens[ctr], '\r')));
		tokens[++ctr] = ptr+1) {
			*ptr = '\0';
	}

	/* Stage 0-2: Parse labels*/
	/* Stage 3: Assemble */
// XXX: stages must be dinamic. until all equs have been resolved
#define STAGES 5
	pc = a->pc;
	for (stage = 0; stage < STAGES; stage++) {
		if (stage < 2 && !labels)
			continue;
		r_asm_set_pc (a, pc);
		for (idx = ret = i = j = 0, off = a->pc, acode->buf_hex[0] = '\0';
				i <= ctr; i++, idx += ret) {
			memset (buf_token, 0, R_ASM_BUFSIZE);
			strncpy (buf_token, tokens[i], R_ASM_BUFSIZE-1);
			for (ptr_start = buf_token; *ptr_start &&
				isseparator (*ptr_start); ptr_start++);
			ptr = strchr (ptr_start, '#'); /* Comments */
			if (ptr && !R_BETWEEN ('0', ptr[1], '9'))
				*ptr = '\0';
			r_asm_set_pc (a, a->pc + ret);
			off = a->pc;
			ret = 0;
			if (!*ptr_start)
				continue;
			//eprintf ("LINE %d %s\n", stage, ptr_start);
			linenum ++;
			if (labels) /* Labels */
			if ((ptr = strchr (ptr_start, ':'))) {
				char food[64];
				//if (stage != 2) {
					*ptr = 0;
					snprintf (food, sizeof (food), "0x%"PFMT64x"", off);
// TODO: warning when redefined
					r_asm_code_set_equ (acode, ptr_start, food);
				//}
				ptr_start = ptr + 1;
			}
			if (*ptr_start == '\0') {
				ret = 0;
				continue;
			} else if (*ptr_start == '.') { /* pseudo */
				ptr = ptr_start;
				if (!strncmp (ptr, ".intel_syntax", 13))
					a->syntax = R_ASM_SYNTAX_INTEL;
				else if (!strncmp (ptr, ".att_syntax", 10))
					a->syntax = R_ASM_SYNTAX_ATT;
				else if (!strncmp (ptr, ".string ", 8)) {
					r_str_chop (ptr+8);
					ret = r_asm_pseudo_string (&op, ptr+8, 1);
				} else if (!strncmp (ptr, ".ascii ", 7)) {
					ret = r_asm_pseudo_string (&op, ptr+7, 0);
				} else if (!strncmp (ptr, ".align", 7)) {
					ret = r_asm_pseudo_align (&op, ptr+7);
				} else if (!strncmp (ptr, ".arm", 4)) {
					r_asm_use (a, "arm");
					r_asm_set_bits (a, 32);
					ret = 0;
				} else if (!strncmp (ptr, ".thumb", 6)) {
					r_asm_use (a, "arm");
					r_asm_set_bits (a, 16);
					ret = 0;
				} else if (!strncmp (ptr, ".arch ", 6))
					ret = r_asm_pseudo_arch (a, ptr+6);
				else if (!strncmp (ptr, ".bits ", 6))
					ret = r_asm_pseudo_bits (a, ptr+6);
				else if (!strncmp (ptr, ".fill ", 6))
					ret = r_asm_pseudo_fill (&op, ptr+6);
				else if (!strncmp (ptr, ".kernel ", 8))
					r_syscall_setup (a->syscall, a->cur->arch, ptr+8, a->bits);
				else if (!strncmp (ptr, ".os ", 4))
					r_syscall_setup (a->syscall, a->cur->arch, ptr+4, a->bits);
				else if (!strncmp (ptr, ".hex ", 5))
					ret = r_asm_pseudo_hex (&op, ptr+5);
				else if ((!strncmp (ptr, ".int16 ", 7)) || !strncmp (ptr, ".short ", 7))
					ret = r_asm_pseudo_int16 (a, &op, ptr+7);
				else if (!strncmp (ptr, ".int32 ", 7))
					ret = r_asm_pseudo_int32 (a, &op, ptr+7);
				else if (!strncmp (ptr, ".int64 ", 7))
					ret = r_asm_pseudo_int64 (a, &op, ptr+7);
				else if (!strncmp (ptr, ".size", 5))
					ret = R_TRUE; // do nothing, ignored
				else if (!strncmp (ptr, ".section", 8))
					ret = R_TRUE; // do nothing, ignored
				else if ((!strncmp (ptr, ".byte ", 6)) || (!strncmp (ptr, ".int8 ", 6)))
					ret = r_asm_pseudo_byte (&op, ptr+6);
				else if (!strncmp (ptr, ".glob", 5)) { // .global .globl
				//	eprintf (".global directive not yet implemented\n");
					ret = 0;
					continue;
				} else if (!strncmp (ptr, ".equ ", 5)) {
					ptr2 = strchr (ptr+5, ',');
					if (!ptr2)
						ptr2 = strchr (ptr+5, '=');
					if (!ptr2)
						ptr2 = strchr (ptr+5, ' ');
					if (ptr2) {
						*ptr2 = '\0';
						r_asm_code_set_equ (acode, ptr+5, ptr2+1);
					} else eprintf ("Invalid syntax for '.equ': Use '.equ <word> <word>'\n");
				} else if (!strncmp (ptr, ".org ", 5)) {
					ret = r_asm_pseudo_org (a, ptr+5);
					off = a->pc;
				} else if (!strncmp (ptr, ".text", 5)) {
					acode->code_offset = a->pc;
				} else if (!strncmp (ptr, ".data", 5)) {
					acode->data_offset = a->pc;
				} else {
					eprintf ("Unknown directive (%s)\n", ptr);
					return r_asm_code_free (acode);
				}
				if (!ret)
					continue;
				if (ret < 0) {
					eprintf ("!!! Oops\n");
					return r_asm_code_free (acode);
				}
			} else { /* Instruction */
				char *str = ptr_start;
				ptr_start = r_str_chop (str);
				if (a->ifilter)
					r_parse_parse (a->ifilter, ptr_start, ptr_start);
				if (acode->equs) {
					if (!*ptr_start)
						continue;
					str = r_asm_code_equ_replace (acode, strdup (ptr_start));
					ret = r_asm_assemble (a, &op, str);
					free (str);
				} else {
					if (!*ptr_start)
						continue;
					ret = r_asm_assemble (a, &op, ptr_start);
				}
			}
			if (stage == STAGES-1) {
				if (ret < 1) {
					eprintf ("Cannot assemble '%s' at line %d\n", ptr_start, linenum);
					return r_asm_code_free (acode);
				}
				acode->len = idx + ret;
				if (!(acode->buf = realloc (acode->buf, (idx+ret)*2)))
					return r_asm_code_free (acode);
				if (!(acode->buf_hex = realloc (acode->buf_hex, (acode->len*2)+1)))
					return r_asm_code_free (acode);
				memcpy (acode->buf+idx, op.buf, ret);
				strcat (acode->buf_hex, op.buf_hex);
			}
		}
	}
	free (lbuf);
	return acode;
}

R_API int r_asm_modify(RAsm *a, ut8 *buf, int field, ut64 val) {
	int ret = R_FALSE;
	if (a->cur && a->cur->modify)
		ret = a->cur->modify (a, buf, field, val);
	return ret;
}

R_API char *r_asm_op_get_hex(RAsmOp *op) {
	return strdup (op->buf_hex);
}

R_API char *r_asm_op_get_asm(RAsmOp *op) {
	return strdup (op->buf_asm);
}

R_API int r_asm_op_get_size(RAsmOp *op) {
	int len;
	if (!op) return 0;
	len = op->size - op->payload;
	if (len<1) len = 1;
	return len;
}

R_API int r_asm_get_offset(RAsm *a, int type, int idx) { // link to rbin
	if (a && a->binb.bin && a->binb.get_offset)
		return a->binb.get_offset (a->binb.bin, type, idx);
	return -1;
}

R_API char *r_asm_describe(RAsm *a, const char* str) {
	if (a->pair)
		return sdb_get (a->pair, str, 0);
	return NULL;
}

R_API RList* r_asm_get_plugins(RAsm *a) {
	return a->plugins;
}
