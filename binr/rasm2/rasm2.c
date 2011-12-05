/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <r_types.h>
#include <r_asm.h>
#include <r_util.h>
#include <r_lib.h>

static struct r_lib_t *l;
static struct r_asm_t *a;
static int coutput = R_FALSE;

static void r_asm_list(RAsm *a) {
	RAsmPlugin *h;
	RListIter *iter;
	r_list_foreach (a->plugins, iter, h) {
		const char *feat="---";
		if (h->assemble && h->disassemble)  feat = "ad";
		if (h->assemble && !h->disassemble) feat = "a_";
		if (!h->assemble && h->disassemble) feat = "_d";
		printf ("%s  %-8s  %s\n", feat, h->name, h->desc);
	}
}

static int rasm_show_help() {
	printf ("rasm2 [-e] [-o offset] [-a arch] [-s syntax] -d \"opcode\"|\"hexpairs\"|- [-f file ..]\n"
		" -d           Disassemble from hexpair bytes\n"
		" -D           Disassemble showing hexpair and opcode\n"
		" -f           Read data from file\n"
		" -F [in:out]  Specify input and/or output filters (att2intel, x86.pseudo, ...)\n"
		" -o [offset]  Set start address for code (0x%08"PFMT64x")\n"
		" -a [arch]    Set architecture plugin\n"
		" -b [bits]    Set architecture bits\n"
		" -s [syntax]  Select syntax (intel, att)\n"
		" -B           Binary input/output (-l is mandatory for binary input)\n"
		" -l [int]     Input/Output length\n"
		" -C           Output in C format\n"
		" -L           List supported asm plugins\n"
		" -e           Use big endian\n"
		" -v           Show version information\n"
		" If '-l' value is greater than output length, output is padded with nops\n"
		" If the last argument is '-' reads from stdin\n", R_SYS_BASE);
	return 0;
}

static int rasm_disasm(char *buf, ut64 offset, ut64 len, int ascii, int bin, int hex) {
	struct r_asm_code_t *acode;
	ut8 *data = NULL;
	char *ptr = buf;
	int ret = 0;
	ut64 word = 0, clen = 0; 

	if (bin) {
		if (len<0)
			return R_FALSE;
		clen = len; // XXX
		data = (ut8*)buf;
	} else if (ascii) {
		clen = strlen (buf);
		data = (ut8*)buf;
	} else {
		for (; *ptr; ptr++)
			if (*ptr!=' ' && *ptr!='\n' && *ptr!='\r')
				if (!(++word%2)) clen++;
		data = malloc (clen+1);
		if (r_hex_str2bin (buf, data)==-1)
			goto beach;
	}

	if (!len || clen <= len)
		len = clen;

	if (hex) {
		RAsmOp op;
		r_asm_set_pc (a, offset);
		while (r_asm_disassemble (a, &op, data+ret, len-ret) != -1) {
			printf ("0x%08"PFMT64x"  %d %12s %s\n", 
				a->pc, op.inst_len, op.buf_hex, op.buf_asm);
			ret += op.inst_len;
			r_asm_set_pc (a, offset+ret);
		}
	} else {
		r_asm_set_pc (a, offset);
		if (!(acode = r_asm_mdisassemble (a, data, len)))
			goto beach;
		printf ("%s", acode->buf_asm);
		ret = acode->len;
		r_asm_code_free (acode);
	}
beach:
	if (data && data != (ut8*)buf) free (data);
	return ret;
}

static void print_buf(char *str) {
	int i;
	if (coutput) {
		printf ("\"");
		for (i=1; *str; str+=2, i+=2) {
			if (!(i%41)) {
				printf ("\" \\\n\"");
				i=1;
			}
			printf ("\\x%c%c", *str, str[1]);
		}
		printf ("\"\n");
	} else printf ("%s\n", str);
}

static int rasm_asm(char *buf, ut64 offset, ut64 len, int bin) {
	struct r_asm_code_t *acode;
	struct r_asm_op_t op;
	int ret, idx, i;

	r_asm_set_pc (a, offset);
	if (!(acode = r_asm_massemble (a, buf)))
		return 0;
	if (bin)
		for (i = 0; i < acode->len; i++)
			printf ("%c", acode->buf[i]);
	else print_buf (acode->buf_hex);
	for (ret = 0, idx = acode->len; idx < len; idx+=ret) {
		if (!(ret = r_asm_assemble (a, &op, "nop")))
			return 0;
		if (bin)
			for (i = 0; i < ret; i++)
				printf ("%c", op.buf[i]);
		else print_buf (op.buf_hex);
	}
	if (!bin && len && idx == len) printf ("\n");
	r_asm_code_free (acode);
	return idx;
}

/* asm callback */
static int __lib_asm_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	RAsmPlugin *hand = (struct r_asm_plugin_t *)data;
	r_asm_add (a, hand);
	return R_TRUE;
}
static int __lib_asm_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

int main(int argc, char *argv[]) {
	char *arch = NULL, *file = NULL, *filters = NULL;
	ut64 offset = R_SYS_BASE;
	int dis = 0, ascii = 0, bin = 0, ret = 0, bits = 32, c;
	ut64 len = 0, idx = 0;

	a = r_asm_new ();
	l = r_lib_new ("radare_plugin");
	r_lib_add_handler (l, R_LIB_TYPE_ASM, "(dis)assembly plugins",
		&__lib_asm_cb, &__lib_asm_dt, NULL);
	r_lib_opendir (l, r_sys_getenv ("LIBR_PLUGINS"));

	if (argc<2)
		return rasm_show_help ();

	r_asm_use (a, R_SYS_ARCH);
	while ((c = getopt (argc, argv, "DCeva:b:s:do:Bl:hLf:F:")) != -1) {
		switch (c) {
		case 'D':
			dis = 2;
			break;
		case 'f':
			file = optarg;
			break;
		case 'F':
			filters = optarg;
			break;
		case 'C':
			coutput = R_TRUE;
			break;
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = r_num_math (NULL, optarg);
			break;
		case 's':
			if (!strcmp (optarg, "att"))
				r_asm_set_syntax (a, R_ASM_SYNTAX_ATT);
			else r_asm_set_syntax (a, R_ASM_SYNTAX_INTEL);
			break;
		case 'd':
			dis = 1;
			break;
		case 'o':
			offset = r_num_math (NULL, optarg);
			break;
		case 'B':
			bin = 1;
			break;
		case 'l':
			len = r_num_math (NULL, optarg);
			break;
		case 'L':
			r_asm_list (a);
			exit (1);
		case 'e':
			r_asm_set_big_endian (a, R_TRUE);
			break;
		case 'v':
			printf ("rasm2 v"R2_VERSION"\n");
			return 0;
		case 'h':
			return rasm_show_help ();
		}
	}

	if (arch) {
		if (!r_asm_use (a, arch)) {
			eprintf ("Error: Unknown asm plugin '%s'\n", arch);
			return 0;
		}
		if (!strcmp (arch, "bf"))
			ascii = 1;
	} else if (!r_asm_use (a, "x86")) {
		eprintf ("Error: Cannot find asm.x86 plugin\n");
		return 0;
	}
	if (!r_asm_set_bits (a, bits))
		eprintf ("WARNING: cannot set asm backend to %d bits\n", bits);

	if (filters) {
		char *p = strchr (filters, ':');
		if (p) {
			*p = 0;
			if (*filters) r_asm_filter_input (a, filters);
			if (p[1]) r_asm_filter_output (a, p+1);
			*p = ':';
		} else {
			if (dis) r_asm_filter_output (a, filters);
			else r_asm_filter_input (a, filters);
		}
	}

	if (file) {
		char *content;
		int length;
		if (!strcmp (file, "-")) {
			char buf[R_ASM_BUFSIZE]; // TODO: Fix this limitation
			ret = fread (buf, 1, sizeof (buf)-1, stdin);
			if (ret == R_ASM_BUFSIZE)
				eprintf ("WARNING: Cannot slurp more from stdin\n");
			if (ret>=0)
				buf[ret] = '\0';
			if (dis)
				ret = rasm_disasm (buf, offset, len, ascii, bin, dis-1);
			else ret = rasm_asm (buf, offset, len, bin);
		} else {
			content = r_file_slurp (file, &length);
			if (content) {
				content[length] = '\0';
				if (dis) ret = rasm_disasm (content, offset, len, ascii, bin, dis-1);
				else ret = rasm_asm (content, offset, len, bin);
				free (content);
			} else eprintf ("Cannot open file %s\n", file);
		}
	} else if (argv[optind]) {
		if (!strcmp (argv[optind], "-")) {
			char buf[R_ASM_BUFSIZE];
			for (;;) {
				fgets (buf, sizeof (buf)-1, stdin);
				if ((!bin || !dis) && feof (stdin))
					break;
				if (!bin || !dis) buf[strlen (buf)-1]='\0';
				if (dis) ret = rasm_disasm (buf, offset, len, ascii, bin, dis-1);
				else ret = rasm_asm (buf, offset, len, bin);
				idx += ret;
				offset += ret;
				if (!ret) {
					eprintf ("invalid\n");
					return 0;
				}
				if (len && idx >= len)
					break;
			}
			return idx;
		}
		if (dis) ret = rasm_disasm (argv[optind], offset, len, ascii, bin, dis-1);
		else ret = rasm_asm (argv[optind], offset, len, bin);
		if (!ret) eprintf ("invalid\n");
		return ret;
	}
	return 0;
}
