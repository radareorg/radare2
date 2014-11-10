/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_types.h>
#include <r_anal.h>
#include <r_lib.h>
#include <r_util.h>
#include <getopt.c>

/* anal callback */
static int __lib_anal_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	RAnal *anal = (RAnal *)user;
	RAnalPlugin *plugin = (RAnalPlugin *)data;
	r_anal_add (anal, plugin);
	return R_TRUE;
}

static int __lib_anal_dt(struct r_lib_plugin_t *pl, void *p, void *u) {
	return R_TRUE;
}

static char *stackop2str(int type) {
	switch (type) {
		case R_ANAL_STACK_NULL:     return strdup ("null");
		case R_ANAL_STACK_NOP:      return strdup ("nop");
		//case R_ANAL_STACK_INCSTACK: return strdup ("incstack");
		case R_ANAL_STACK_GET:      return strdup ("get");
		case R_ANAL_STACK_SET:      return strdup ("set");
	}
	return strdup ("unknown");
}

static char *optype2str(int type) {
	switch (type) {
		case R_ANAL_OP_TYPE_JMP:   return strdup ("jmp");
		case R_ANAL_OP_TYPE_UJMP:  return strdup ("ujmp");
		case R_ANAL_OP_TYPE_CJMP:  return strdup ("cjmp");
		case R_ANAL_OP_TYPE_CALL:  return strdup ("call");
		case R_ANAL_OP_TYPE_UCALL: return strdup ("ucall");
		case R_ANAL_OP_TYPE_REP:   return strdup ("rep");
		case R_ANAL_OP_TYPE_RET:   return strdup ("ret");
		case R_ANAL_OP_TYPE_ILL:   return strdup ("ill");
		case R_ANAL_OP_TYPE_NOP:   return strdup ("nop");
		case R_ANAL_OP_TYPE_MOV:   return strdup ("mov");
		case R_ANAL_OP_TYPE_TRAP:  return strdup ("trap");
		case R_ANAL_OP_TYPE_SWI:   return strdup ("swi");
		case R_ANAL_OP_TYPE_UPUSH: return strdup ("upush");
		case R_ANAL_OP_TYPE_PUSH:  return strdup ("push");
		case R_ANAL_OP_TYPE_POP:   return strdup ("pop");
		case R_ANAL_OP_TYPE_CMP:   return strdup ("cmp");
		case R_ANAL_OP_TYPE_ADD:   return strdup ("add");
		case R_ANAL_OP_TYPE_SUB:   return strdup ("sub");
		case R_ANAL_OP_TYPE_MUL:   return strdup ("mul");
		case R_ANAL_OP_TYPE_DIV:   return strdup ("div");
		case R_ANAL_OP_TYPE_SHR:   return strdup ("shr");
		case R_ANAL_OP_TYPE_SHL:   return strdup ("shl");
		case R_ANAL_OP_TYPE_OR:    return strdup ("or");
		case R_ANAL_OP_TYPE_AND:   return strdup ("and");
		case R_ANAL_OP_TYPE_XOR:   return strdup ("xor");
		case R_ANAL_OP_TYPE_NOT:   return strdup ("not");
		case R_ANAL_OP_TYPE_STORE: return strdup ("store");
		case R_ANAL_OP_TYPE_LOAD:  return strdup ("load");
	}
	return strdup ("unknown");

}

static int analyze(RAnal *anal, RAnalOp *op, ut64 offset, ut8* buf, int len) {
	char *bytes, *optype = NULL, *stackop = NULL;
	int ret;

	ret = r_anal_op (anal, op, offset, buf, len);
	if (ret) {
		stackop = stackop2str (op->stackop);
		optype = optype2str (op->type);
		bytes = r_hex_bin2strdup (buf, ret);
		printf ("bytes:    %s\n", bytes);
		printf ("type:     %s\n", optype);
		if (op->jump != -1LL)
			printf ("jump:     0x%08"PFMT64x"\n", op->jump);
		if (op->fail != -1LL)
			printf ("fail:     0x%08"PFMT64x"\n", op->fail);
		//if (op->ref != -1LL)
		//	printf ("ref:      0x%08"PFMT64x"\n", op->ref);
		if (op->val != -1LL)
			printf ("value:    0x%08"PFMT64x"\n", op->val);
		printf ("stackop:  %s\n", stackop);
		printf ("esil:     %s\n", r_strbuf_get (&op->esil));
		printf ("stackptr: %"PFMT64d"\n", op->stackptr);
		printf ("decode str: %s\n", r_anal_op_to_string (anal, op));
		printf ("--\n");
		free (optype);
		free (stackop);
		free (bytes);
	}
	return ret;
}

static int usage() {
	printf ("ranal2 [opts] hexpairs|-\n"
			" -a [arch]    Set architecture plugin\n"
			" -b [bits]    Set architecture bits\n"
			" -B           Binary input (-l is mandatory for binary input)\n"
			" -h           This help\n"
			" -l [len]     Input length\n"
			" -L           List supported analysis plugins\n"
			" -o [offset]  Offset where this opcode is suposed to be\n"
			" If the last argument is '-' reads from stdin\n");
	return 1;
}

int main(int argc, char **argv) {
	RLib *lib;
	RAnal *anal = r_anal_new ();
	RAnalOp *op = r_anal_op_new ();
	ut8 *ptr, *buf = NULL, *data = NULL;
	ut64 offset = 0x8048000LL;
	char *arch = NULL;
	int bin = R_FALSE, len = 0, bits = 32;
	int c, idx, ret, tlen, word;

	lib = r_lib_new ("radare_plugin");
	r_lib_add_handler (lib, R_LIB_TYPE_ANAL, "analysis plugins",
		&__lib_anal_cb, &__lib_anal_dt, anal);
	r_lib_opendir (lib, r_sys_getenv ("LIBR_PLUGINS"));

	while ((c = getopt (argc, argv, "a:b:Bhl:Lo:")) != -1) {
		switch (c) {
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = r_num_math (NULL, optarg);
			break;
		case 'B':
			bin = R_TRUE;
			break;
		case 'h':
			return usage ();
		case 'l':
			len = r_num_math (NULL, optarg);
			break;
		case 'L':
			return r_anal_list (anal);
		case 'o':
			offset = r_num_math (NULL, optarg);
			break;
		}
	}
	if (!argv[optind] || (bin && !len))
		return usage ();
	/* Set default options */
	if (arch) {
		if (!r_anal_use (anal, arch)) {
			eprintf ("Invalid plugin\n");
			return 1;
		}
	} else r_anal_use (anal, "x86");
	if (!r_anal_set_bits (anal, bits))
		r_anal_set_bits (anal, 32);
	/* Get input & convert to bin if necessary */
	if (argv[optind][0] == '-') {
		idx = 0;
		while (R_TRUE) {
			if (!(buf = realloc (buf, idx+1024)))
				return 1;
			fgets ((char*)buf+idx, 1024, stdin);
			if ((!bin && feof (stdin)) ||(len && idx >= len))
				break;
			idx += 1023;
		}
	} else {
		if (!(buf = (ut8 *)strdup (argv[optind])))
			return 1;
	}
	if (bin) {
		data = (ut8*)buf;
	} else {
		ptr = buf, word = tlen = 0;
		while (ptr[0]) {
			int p = *ptr;
			if (p!= ' ' && p!= '\n' && p!= '\r')
				if (0==(++word%2)) tlen++;
			ptr += 1;
		}
		data = malloc (tlen+1);
		if (!data) {
			r_anal_free (anal);
			r_anal_op_free (op);
			return 1;
		}
		r_hex_str2bin ((char *)buf, data);
		if (!len || len > tlen) len = tlen;
		free (buf);
	}
	/* Analyze */
	for (idx=ret=0; idx<len; idx+=ret) {
		if (!(ret = analyze (anal, op, offset+idx, data+idx, len-idx))) {
			eprintf ("Ooops\n");
			free (data);
			r_anal_free (anal);
			r_anal_op_free (op);
			return 1;
		}
	}
	free (data);
	r_anal_free (anal);
	r_anal_op_free (op);
	return 0;
}
