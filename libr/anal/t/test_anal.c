#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>
#include <getopt.h>

static int usage() {
	printf ("test_anal -l len [-a arch] [-b bits] [-o offset]\n"
			" -a [arch]    Set architecture plugin\n"
			" -b [bits]    Set architecture bits\n"
			" -h           This help\n"
			" -l [len]     Input length\n"
			" -o [offset]  Offset where this opcode is suposed to be\n");
	return 1;
}

static int analyze(RAnal *anal, RAnalOp *aop, ut64 offset, ut8* buf, int len) {
	int ret;

	ret = r_anal_aop (anal, aop, offset, buf, len);
	if (ret) {
		eprintf ("jump:     0x%08"PFMT64x"\n"
				 "fail:     0x%08"PFMT64x"\n"
				 "ref:      0x%08"PFMT64x"\n"
				 "value:    0x%08"PFMT64x"\n"
				 "stackptr: %"PFMT64d"\n",
				 aop->jump, aop->fail, aop->ref, aop->value, aop->stackptr);
	}
	return ret;
}

int main(int argc, char **argv) {
	RAnal *anal = r_anal_new ();
	RAnalOp *aop = r_anal_aop_new ();
	ut8 *buf;
	ut64 offset = 0x8048000LL;
	char *arch = NULL;
	int c, idx, ret, len = 0, bits = 32;

	while ((c = getopt (argc, argv, "a:b:hl:o:")) != -1) {
		switch (c) {
		case 'a':
			arch = optarg;
			break;
		case 'b':
			bits = r_num_math (NULL, optarg);
			break;
		case 'h':
			return usage ();
		case 'l':
			len = r_num_math (NULL, optarg);
			break;
		case 'o':
			offset = r_num_math (NULL, optarg);
			break;
		}
	}
	if (!len)
		return usage ();
	if (!(buf = malloc (len+1)))
		return 1;
	if (arch) {
		if (!r_anal_use (anal, arch)) {
			eprintf ("Invalid plugin\n");
			return 1;
		}
	} else r_anal_use (anal, "x86_x86im");
	if (!r_anal_set_bits (anal, bits))
		r_anal_set_bits (anal, 32);
	fgets ((char*)buf, len+1, stdin);
	for (idx=ret=0; idx<len; idx+=ret) {
		if (!(ret = analyze (anal, aop, offset+idx, buf+idx, len-idx))) {
			eprintf ("Ooops\n");
			free (buf);
			r_anal_free (anal);
			r_anal_aop_free (aop);
			return 1;
		}
	}
	free (buf);
	r_anal_free (anal);
	r_anal_aop_free (aop);
	return 0;
}
