/* radare - LGPL - Copyright 2009-2013 - pancake, nibble */

#include <stdio.h>
#include <string.h>
#include <getopt.c> /* getopt.h is not portable :D */
#include <r_types.h>
#include <r_asm.h>
#include <r_util.h>
#include <r_lib.h>
#include "../blob/version.c"

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
		printf ("%s  %-11s  %s\n", feat, h->name, h->desc);
	}
}

static int rasm_show_help(int v) {
	printf ("Usage: rasm2 [-CdDehLBvw] [-a arch] [-b bits] [-o addr] [-s syntax]\n"
		"             [-f file] [-F fil:ter] [-l len] 'code'|hexpairs|-\n");
	if (v)
	printf (" -a [arch]    Set assemble/disassemble plugin (RASM2_ARCH)\n"
		" -b [bits]    Set cpu register size (8, 16, 32, 64) (RASM2_BITS)\n"
		" -C           Output in C format\n"
		" -d, -D       Disassemble from hexpair bytes (-D show hexpairs)\n"
		" -e           Use big endian instead of little endian\n"
		" -f [file]    Read data from file\n"
		" -F [in:out]  Specify input and/or output filters (att2intel, x86.pseudo, ...)\n"
		" -h           Show this help\n"
		" -l [len]     Input/Output length\n"
		" -L           List supported asm plugins\n"
		" -o [offset]  Set start address for code (default 0)\n"
		" -s [syntax]  Select syntax (intel, att)\n"
		" -B           Binary input/output (-l is mandatory for binary input)\n"
		" -v           Show version information\n"
		" -w           What's this instruction for? describe opcode\n"
		" If '-l' value is greater than output length, output is padded with nops\n"
		" If the last argument is '-' reads from stdin\n");
	return 0;
}

static int rasm_disasm(char *buf, ut64 offset, int len, int bits, int ascii, int bin, int hex) {
	RAsmCode *acode;
	ut8 *data = NULL;
	char *ptr = buf;
	int ret = 0;
	ut64 word = 0, clen = 0; 
	if (bits == 1)
		len /= 8;

	if (bin) {
		if (len<0) return R_FALSE;
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
		while (len-ret > 0 && r_asm_disassemble (a, &op, data+ret, len-ret) != -1) {
			if (op.inst_len<1) break;
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

static int rasm_asm(char *buf, ut64 offset, ut64 len, int bits, int bin) {
	RAsmCode *acode;
	int i, j, ret = 0;

	r_asm_set_pc (a, offset);
	if (!(acode = r_asm_massemble (a, buf)))
		return 0;
	if (acode->len) {
		ret = acode->len;
		if (bin) {
			write (1, acode->buf, acode->len);
		} else {
			int b = acode->len;
			if (bits==1) {
				int bytes = (b/8)+1;
				for (i=0; i<bytes; i++)
					for (j=0; j<8 && b--; j++)
						printf ("%c", (acode->buf[i] & (1<<j))?'1':'0');
				printf ("\n");
			} else print_buf (acode->buf_hex);
		}
	}
	r_asm_code_free (acode);
	return ret > 0;
}

/* asm callback */
static int __lib_asm_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	RAsmPlugin *hand = (struct r_asm_plugin_t *)data;
	r_asm_add (a, hand);
	return R_TRUE;
}
static int __lib_asm_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

int main(int argc, char *argv[]) {
	const char *env_arch = r_sys_getenv ("RASM2_ARCH");
	const char *env_bits = r_sys_getenv ("RASM2_BITS");
	char buf[R_ASM_BUFSIZE];
	char *arch = NULL, *file = NULL, *filters = NULL;
	ut64 offset = 0;
	int dis = 0, ascii = 0, bin = 0, ret = 0, bits = 32, c, whatsop = 0;
	ut64 len = 0, idx = 0;

	a = r_asm_new ();
	l = r_lib_new ("radare_plugin");
	r_lib_add_handler (l, R_LIB_TYPE_ASM, "(dis)assembly plugins",
		&__lib_asm_cb, &__lib_asm_dt, NULL);
	r_lib_opendir (l, r_sys_getenv ("LIBR_PLUGINS"));

	if (argc<2)
		return rasm_show_help (0);

	r_asm_use (a, R_SYS_ARCH);
	while ((c = getopt (argc, argv, "DCeva:b:s:do:Bl:hLf:F:w")) != -1) {
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
			return blob_version ("rasm2");
		case 'h':
			return rasm_show_help (1);
		case 'w':
			whatsop = R_TRUE;
			break;
		}
	}

	if (arch) {
		if (!r_asm_use (a, arch)) {
			eprintf ("rasm2: Unknown asm plugin '%s'\n", arch);
			return 0;
		}
		if (!strcmp (arch, "bf"))
			ascii = 1;
	} else if (env_arch) {
		if (!r_asm_use (a, env_arch)) {
			eprintf ("rasm2: Unknown asm plugin '%s'\n", env_arch);
			return 0;
		}
	} else if (!r_asm_use (a, "x86")) {
		eprintf ("rasm2: Cannot find asm.x86 plugin\n");
		return 0;
	}
	r_asm_set_bits (a, (env_bits && *env_bits)? atoi (env_bits): bits);

	if (whatsop) {
		const char *s = r_asm_describe (a, argv[optind]);
		if (s) {
			printf ("%s\n", s);
			return 0;
		}
		return 1;
	}

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
		int length = 0;
		if (!strcmp (file, "-")) {
			ret = read (0, buf, sizeof (buf)-1);
			if (ret == R_ASM_BUFSIZE)
				eprintf ("rasm2: Cannot slurp all stdin data\n");
			if (ret>=0) // only for text
				buf[ret] = '\0';
			len = ret;
			if (dis) ret = rasm_disasm (buf, offset, len,
					a->bits, ascii, bin, dis-1);
			else ret = rasm_asm (buf, offset, len, a->bits, bin);
		} else {
			content = r_file_slurp (file, &length);
			if (content) {
				if (len && len>0 && len<length)
					length = len;
				content[length] = '\0';
				if (dis) ret = rasm_disasm (content, offset,
					length, a->bits, ascii, bin, dis-1);
				else ret = rasm_asm (content, offset, length, a->bits, bin);
				free (content);
			} else eprintf ("rasm2: Cannot open file %s\n", file);
		}
	} else if (argv[optind]) {
		if (!strcmp (argv[optind], "-")) {
			int length;
			do {
				length = read (0, buf, sizeof (buf)-1);
				if (length<1) break;
				if (len>0 && len < length)
					length = len;
				if ((!bin || !dis) && feof (stdin))
					break;
				if (!bin || !dis) buf[strlen (buf)-1]='\0';
				if (dis) ret = rasm_disasm (buf, offset,
					length, a->bits, ascii, bin, dis-1);
				else ret = rasm_asm (buf, offset, length, a->bits, bin);
				idx += ret;
				offset += ret;
				if (!ret) return 0;
			} while (!len || idx<length);
			return idx;
		}
		if (dis) ret = rasm_disasm (argv[optind], offset, len,
			a->bits, ascii, bin, dis-1);
		else ret = rasm_asm (argv[optind], offset, len, a->bits, bin);
		if (!ret) eprintf ("invalid\n");
		return !ret;
	}
	return 0;
}
