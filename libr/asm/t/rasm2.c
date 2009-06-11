/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <r_types.h>
#include <r_asm.h>
#include <r_util.h>
#include <r_lib.h>


static struct r_lib_t l;
static struct r_asm_t a;

static int rasm_show_help()
{
	printf ("rasm2 [-e] [-o offset] [-a arch] [-s syntax] -d \"opcode\"|\"hexpairs\"|-\n"
		" -d           Disassemble from hexpair bytes\n"
		" -o [offset]  Offset where this opcode is suposed to be\n"
		" -a [arch]    Set architecture plugin\n"
		" -b [bits]    Set architecture bits\n"
		" -s [syntax]  Select syntax (intel, att)\n"
		" -B           Binary input/output (-l is mandatory for binary input)\n"
		" -l [int]     Input/Output length\n"
		" -L           List supported asm plugins\n"
		" -e           Use big endian\n"
		" If '-l' value is greater than output length, output is padded with nops\n"
		" If the last argument is '-' reads from stdin\n");
	return 0;
}

static int rasm_disasm(char *buf, u64 offset, u64 len, int ascii, int bin)
{
	struct r_asm_aop_t aop;
	u8 *data;
	char *ptr = buf;
	int ret = 0;
	u64 word = 0, clen = 0; 

	if (bin) {
		clen = len; //XXX
		data = (u8*)buf;
	} else if (ascii) {
		clen = strlen(buf);
		data = (u8*)buf;
	} else {
		while(ptr[0]) {
			if (ptr[0]!= ' ')
				if (0==(++word%2))clen++;
			ptr += 1;
		}
		data = alloca(clen);
		r_hex_str2bin(buf, data);
	}

	if (!len || clen <= len)
		len = clen;

	r_asm_set_pc(&a, offset);
	if (!(ret = r_asm_mdisassemble(&a, &aop, data, len)))
		return 0;
	printf("%s\n", aop.buf_asm);

	return ret;
}

static int rasm_asm(char *buf, u64 offset, u64 len, int bin)
{
	struct r_asm_aop_t aop;
	int ret, idx, i;

#if 0 
	/* TODO: Arch, syntax... */
	if (!r_asm_set(&a, "asm_x86_olly")) {
		fprintf(stderr, "Error: Cannot find asm_x86 plugin\n");
		return 1;
	}
#endif 
	r_asm_set_pc(&a, offset);
	if (!(idx = r_asm_massemble(&a, &aop, buf)))
		return 0;
	if (bin)
		for (i = 0; i < idx; i++)
			printf("%c", aop.buf[i]);
	else printf("%s\n", aop.buf_hex);
	for (ret = 0; idx < len; idx+=ret) {
		if (!(ret = r_asm_assemble(&a, &aop, "nop")))
			return 0;
		if (bin)
			for (i = 0; i < ret; i++)
				printf("%c", aop.buf[i]);
		else printf("%s", aop.buf_hex);
	}
	if (!bin && len && idx == len) printf("\n");

	return idx;
}

/* asm callback */
static int __lib_asm_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	struct r_asm_handle_t *hand = (struct r_asm_handle_t *)data;
	//printf(" * Added (dis)assembly handler\n");
	r_asm_add(&a, hand);
	return R_TRUE;
}
static int __lib_asm_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

int main(int argc, char *argv[])
{
	char *arch = NULL;
	u64 offset = 0x8048000;
	int dis = 0, ascii = 0, bin = 0, ret = 0, bits = 32, c;
	u64 len = 0, idx = 0;

	r_asm_init(&a);
	r_lib_init(&l, "radare_plugin");
	r_lib_add_handler(&l, R_LIB_TYPE_ASM, "(dis)assembly plugins",
		&__lib_asm_cb, &__lib_asm_dt, NULL);
	r_lib_opendir(&l, getenv("LIBR_PLUGINS"));

	if (argc<2)
		return rasm_show_help();

	r_asm_set(&a, "asm_x86");
	while ((c = getopt(argc, argv, "a:b:s:do:Bl:hL")) != -1)
	{
		switch( c ) {
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = r_num_math(NULL, optarg);
			break;
		case 's':
			if (!strcmp(optarg, "att"))
				r_asm_set_syntax(&a, R_ASM_SYN_ATT);
			else r_asm_set_syntax(&a, R_ASM_SYN_INTEL);
			break;
		case 'd':
			dis = 1;
			break;
		case 'o':
			offset = r_num_math(NULL, optarg);
			break;
		case 'B':
			bin = 1;
			break;
		case 'l':
			len = r_num_math(NULL, optarg);
			break;
		case 'L':
			r_asm_list(&a);
			exit(1);
		case 'e':
			r_asm_set_big_endian(&a, R_TRUE);
			break;
		case 'h':
			return rasm_show_help();
		}
	}

	if (arch) {
		char *str = malloc(strlen(arch)+10);
		sprintf(str, "asm_%s", arch);
		if (!r_asm_set(&a, str)) {
			fprintf(stderr, "Error: Unknown plugin\n");
			free (str);
			return 0;
		}
		free (str);
		if (!strcmp(arch, "bf"))
			ascii = 1;
	} else if (!r_asm_set(&a, "asm_x86")) {
		fprintf(stderr, "Error: Cannot find asm_x86 plugin\n");
		return 0;
	}
	if (!r_asm_set_bits(&a, bits))
		fprintf(stderr, "cannot set bits (triying with 32)\n");

	if (argv[optind]) {
		if (!strcmp(argv[optind], "-")) {
			char buf[R_ASM_BUFSIZE];
			for(;;) {
				fgets(buf, R_ASM_BUFSIZE, stdin);
				if ((!bin || !dis) && feof(stdin))
					break;
				if (!bin || !dis) buf[strlen(buf)-1]='\0';
				if (dis) {
					ret = rasm_disasm(buf, offset, len, ascii, bin);
				} else {
					ret = rasm_asm(buf, offset, len, bin);
				}
				idx += ret;
				offset += ret;
				if (!ret) {
					fprintf(stderr, "invalid\n");
					return 0;
				}
				if (len && idx >= len)
					break;
			}
			return idx;
		}
		if (dis) ret = rasm_disasm(argv[optind], offset, len, ascii, bin);
		else ret = rasm_asm(argv[optind], offset, len, bin);
		if (!ret) {
			fprintf(stderr, "invalid\n");
			return 0;
		}
		return ret;
	}

	return 0;
}
