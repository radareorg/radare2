#include <r_util.h>
#include <r_types.h>
#include <r_asm.h>
#include <string.h>

static void str_op(char *c) {
	if ((c[0] <= 'Z') && (c[0] >= 'A'))
		c[0] += 0x20;
}

static int gbAsm(RAsm *a, RAsmOp *op, const char *buf) {
	int mn_len, i, len = 1;
	ut32 mn = 0;
	if (!a || !op || !buf)
		return 0;
	strncpy (op->buf_asm, buf, R_ASM_BUFSIZE);
	r_str_replace (op->buf_asm, "  ", " ", R_TRUE);
	r_str_replace (op->buf_asm, " ,", ",", R_TRUE);
	mn_len = r_str_do_until_token (str_op, op->buf_asm, ' ');
	if (mn_len < 2 || mn_len > 4)
		return 0;
	for (i = 0; i < mn_len; i++)
		mn = (mn << 8) | op->buf_asm[i];
	switch (mn) {
		case 0x6e6f70:
			op->buf[0] = 0x00;
			break;
		case 0x726c6361:
			op->buf[0] = 0x07;
			break;
		case 0x72726361:
			op->buf[0] = 0xf0;
			break;
		case 0x73746f70:
			op->buf[0] = 0x10;
			break;
		case 0x726c61:
			op->buf[0] = 0x17;
			break;
		case 0x727261:
			op->buf[0] = 0x1f;
			break;
		case 0x646161:
			op->buf[0] = 0x27;
			break;
		case 0x63706c:
			op->buf[0] = 0x2f;
			break;
		case 0x736366:
			op->buf[0] = 0x37;
			break;
		case 0x636366:
			op->buf[0] = 0x3f;
			break;
		case 0x68616c74:
			op->buf[0] = 0x76;
			break;
		case 0x726574:
			op->buf[0] = 0xc9;
			break;
		case 0x6469:
			op->buf[0] = 0xf3;
			break;
		case 0x6569:
			op->buf[0] = 0xfb;
			break;
		default:
			len = 0;
			break;
	}
	return op->size = len;
}
