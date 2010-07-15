/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

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

// TODO: remove or gtfo
static void r_asm_list(RAsm *a) {
	RAsmPlugin *h;
	RListIter *iter;
	r_list_foreach (a->plugins, iter, h)
		printf ("asm %s\t %s\n", h->name, h->desc);
}

static int rasm_show_help() {
	printf ("rasm2 [-e] [-o offset] [-a arch] [-s syntax] -d \"opcode\"|\"hexpairs\"|- [-f file ..]\n"
		" -d           Disassemble from hexpair bytes\n"
		" -f           Read data from file\n"
		" -o [offset]  Offset where this opcode is suposed to be\n"
		" -a [arch]    Set architecture plugin\n"
		" -b [bits]    Set architecture bits\n"
		" -s [syntax]  Select syntax (intel, att)\n"
		" -B           Binary input/output (-l is mandatory for binary input)\n"
		" -l [int]     Input/Output length\n"
		" -C           Output in C format\n"
		" -L           List supported asm plugins\n"
		" -e           Use big endian\n"
		" -V           Show version information\n"
		" If '-l' value is greater than output length, output is padded with nops\n"
		" If the last argument is '-' reads from stdin\n");
	return 0;
}

static int rasm_disasm(char *buf, ut64 offset, ut64 len, int ascii, int bin) {
	struct r_asm_code_t *acode;
	ut8 *data;
	char *ptr = buf;
	int ret = 0;
	ut64 word = 0, clen = 0; 

	if (bin) {
		clen = len; //XXX
		data = (ut8*)buf;
	} else if (ascii) {
		clen = strlen (buf);
		data = (ut8*)buf;
	} else {
		while (ptr[0]) {
			if (ptr[0]!= ' ' && ptr[0]!= '\n' && ptr[0]!= '\r')
				if (0==(++word%2))clen++;
			ptr += 1;
		}
		data = alloca (clen);
		r_hex_str2bin (buf, data);
	}

	if (!len || clen <= len)
		len = clen;

	r_asm_set_pc (a, offset);
	if (!(acode = r_asm_mdisassemble (a, data, len)))
		return 0;
	printf ("%s\n", acode->buf_asm);
	ret = acode->len;
	r_asm_code_free (acode);

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
	struct r_asm_aop_t aop;
	int ret, idx, i;

#if 0 
	/* TODO: Arch, syntax... */
	if (!r_asm_use(&a, "x86.olly")) {
		fprintf(stderr, "Error: Cannot find asm_x86 plugin\n");
		return 1;
	}
#endif 
	r_asm_set_pc (a, offset);
	if (!(acode = r_asm_massemble (a, buf)))
		return 0;
	if (bin)
		for (i = 0; i < acode->len; i++)
			printf ("%c", acode->buf[i]);
	else print_buf (acode->buf_hex);
	for (ret = 0, idx = acode->len; idx < len; idx+=ret) {
		if (!(ret = r_asm_assemble (a, &aop, "nop")))
			return 0;
		if (bin)
			for (i = 0; i < ret; i++)
				printf ("%c", aop.buf[i]);
		else print_buf (aop.buf_hex);
	}
	if (!bin && len && idx == len) printf ("\n");
	r_asm_code_free (acode);
	return idx;
}

/* asm callback */
static int __lib_asm_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	RAsmPlugin *hand = (struct r_asm_plugin_t *)data;
	r_asm_add (a, hand);
	return R_TRUE;
}
static int __lib_asm_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

int main(int argc, char *argv[])
{
	char *arch = NULL, *file = NULL;
	ut64 offset = 0x8048000;
	int dis = 0, ascii = 0, bin = 0, ret = 0, bits = 32, c;
	ut64 len = 0, idx = 0;

	a = r_asm_new ();
	l = r_lib_new ("radare_plugin");
	r_lib_add_handler (l, R_LIB_TYPE_ASM, "(dis)assembly plugins",
		&__lib_asm_cb, &__lib_asm_dt, NULL);
	r_lib_opendir (l, r_sys_getenv ("LIBR_PLUGINS"));

	if (argc<2)
		return rasm_show_help ();

	r_asm_use (a, "x86"); // XXX: do not harcode default arch
	while ((c = getopt (argc, argv, "CVa:b:s:do:Bl:hLf:")) != -1) {
		switch (c) {
		case 'f':
			file = optarg;
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
		case 'V':
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
		eprintf ("cannot set bits (triying with 32)\n");

	if (file) {
		char *content;
		int length;
		if (!strcmp (file, "-")) {
			char buf[R_ASM_BUFSIZE]; // TODO: Fix this limitation
			ret = fread (buf, 1, R_ASM_BUFSIZE, stdin);
			if (ret == R_ASM_BUFSIZE)
				eprintf ("WARNING: Cannot slurp more from stdin\n");
			if (ret>=0)
				buf[ret] = '\0';
			if (dis) ret = rasm_disasm (buf, offset, len, ascii, bin);
			else ret = rasm_asm (buf, offset, len, bin);
		} else {
			content = r_file_slurp (file, &length);
			if (content) {
				content[length] = '\0';
				if (dis) ret = rasm_disasm (content, offset, len, ascii, bin);
				else ret = rasm_asm (content, offset, len, bin);
				free (content);
			} else eprintf ("Cannot open file %s\n", file);
		}
	} else if (argv[optind]) {
		if (!strcmp (argv[optind], "-")) {
			char buf[R_ASM_BUFSIZE];
			for (;;) {
				fgets (buf, R_ASM_BUFSIZE, stdin);
				if ((!bin || !dis) && feof (stdin))
					break;
				if (!bin || !dis) buf[strlen(buf)-1]='\0';
				if (dis) ret = rasm_disasm (buf, offset, len, ascii, bin);
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
		if (dis) ret = rasm_disasm (argv[optind], offset, len, ascii, bin);
		else ret = rasm_asm (argv[optind], offset, len, bin);
		if (!ret)
			eprintf ("invalid\n");
		return ret;
	}
	return 0;
}
