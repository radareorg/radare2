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
	printf( "rasm2 [-e] [-o offset] [-a arch] [-s syntax] -d \"opcode\"|\"hexpairs\"|-\n"
			" -d           Disassemble from hexpair bytes\n"
			" -o [offset]  Offset where this opcode is suposed to be\n"
			" -a [arch]    Select architecture (x86, arm)\n"
			" -s [syntax]  Select syntax (intel, att, olly)\n"
			" -e           Use big endian\n"
			" If the last argument is '-' reads from stdin\n");
	
	return R_TRUE;
}

static int rasm_disasm(char *buf, u64 offset, char *arch, char *syntax, int big_endian)
{
	struct r_asm_aop_t aop;
	u8 *data;
	char *ptr = buf;
	int ret = 0;
	u64 idx = 0, word = 0, len = 0; 

	while(ptr[0]) {
		if (ptr[0]!= ' ')
			if (0==(++word%2))len++;
		ptr += 1;
	}
	data = alloca(len);
	r_hex_str2bin(buf, data);

	if (!strcmp(arch, "arm"))
		r_asm_set(&a, "asm_arm");
	else r_asm_set(&a, "asm_x86");

	if (syntax != NULL) {
		if (!strcmp(syntax, "att"))
			r_asm_set_syntax(&a, R_ASM_SYN_ATT);
		else if (!strcmp(syntax, "olly"))
			r_asm_set_syntax(&a, R_ASM_SYN_OLLY);
		else r_asm_set_syntax(&a, R_ASM_SYN_INTEL);
	}

	r_asm_set_big_endian(&a, big_endian);
	r_asm_set_pc(&a, offset);

	while (idx < len) {
		r_asm_set_pc(&a, a.pc + ret);
		ret = r_asm_disassemble(&a, &aop, data+idx, len-idx);
		idx += ret;
		printf("%s\n", aop.buf_asm);
	}

	return (int)idx;
}

static int rasm_asm(char *buf, u64 offset, char *arch, char *syntax, int big_endian)
{
	struct r_asm_aop_t aop;
	int ret;


	/* TODO: Arch, syntax... */
	r_asm_set(&a, "asm_x86");
	r_asm_set_syntax(&a, R_ASM_SYN_OLLY);

	r_asm_set_big_endian(&a, big_endian);
	r_asm_set_pc(&a, offset);

	ret = r_asm_assemble(&a, &aop, buf);
	if (!ret)
		printf("invalid\n");
	else printf("%s\n", aop.buf_hex);

	return ret;
}

/* asm callback */
static int __lib_asm_cb(struct r_lib_plugin_t *pl, void *user, void *data)
{
	struct r_asm_handle_t *hand = (struct r_asm_handle_t *)data;
	struct r_core_t *core = (struct r_core_t *)user;
	//printf(" * Added (dis)assembly handler\n");
	r_asm_add(&a, hand);
	return R_TRUE;
}
static int __lib_asm_dt(struct r_lib_plugin_t *pl, void *p, void *u) { return R_TRUE; }

int main(int argc, char *argv[])
{
	char *arch, *syntax;
	u64 offset = 0;
	int big_endian = 0, dis = 0, c;

	if (argc<2)
		return rasm_show_help();

	r_asm_init(&a);
	r_lib_init(&l, "radare_plugin");
	r_lib_add_handler(&l, R_LIB_TYPE_ASM, "(dis)assembly plugins",
		&__lib_asm_cb, &__lib_asm_dt, NULL);
	r_lib_opendir(&l, getenv("LIBR_PLUGINS"));

	while ((c = getopt(argc, argv, "da:s:o:h")) != -1)
	{
		switch( c ) {
		case 'a':
			arch = optarg;
			break;
		case 's':
			syntax = optarg;
			break;
		case 'd':
			dis = 1;
			break;
		case 'o':
			offset = r_num_math(NULL, optarg);
			break;
		case 'e':
			big_endian = 1;
			break;
		case 'h':
			return rasm_show_help();
		}
	}

	if (argv[optind]) {
		if (!strcmp(argv[optind], "-")) {
			char buf[1024];
			for(;;) {
				fgets(buf, 1024, stdin);
				if (feof(stdin))
					break;
				buf[strlen(buf)-1]='\0';
				if (dis)
					offset += rasm_disasm(buf, offset, arch, syntax, big_endian);
				else offset += rasm_asm(buf, offset, arch, syntax, big_endian);
			}
			return 0;
		}
		if (dis)
			return rasm_disasm(argv[optind], offset, arch, syntax, big_endian);
		else return rasm_asm(argv[optind], offset, arch, syntax, big_endian);
	}

	return 0;
}
