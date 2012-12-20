/* disassemble */

static int disassemble_arg(Bitbuf *b, int n) {
	int res = 0;
	// [   1, 2; 0,1; reg,3
	// [   1, 2; 1,1; 1,1; 3,2; imm,32
	// [+- 1, 2; 1,1; 0,1; reg,3; 3,2; imm,32
	// #   0, 2; 3,3; imm,32
	// r   1, 1; 3
	int ret = bitget (b, n);
	// eprintf ("arg %d\n", n);
	res ++;
	if (ret ==-1) {
		eprintf ("IO ERROR\n");
		return 0;
	}
	// printf ("RET [%d] = %d (of %d)\n", n, ret, b->bits);
	if (ret==1) {
		/* opnum >7 && <0x27 */
		int num = bitnum (b, n+res, 3);
		res += 3;
		printf ("r%d", num);
	} else {
		int type, num;
		int opt = bitget (b, n+res);
		res ++;
		if (!opt) {
			// imm32
			type = bitnum (b, n+res, 2);
			res += 2;
			// if
			if (type != 3) {
				eprintf ("unsupported number type size %d\n", type);
			}
			num = bitnum (b, n+res, 32);
			res += 32;
			printf ("0x%x", num);
		} else {
			// reg+imm
			int num = bitnum (b, n+res, 3);
			res += 3;
			printf ("[r%d+", num);
			num = bitnum (b, n+res, 32);
			res += 32;
			printf ("0x%x]", num);
		}
	}
	return res;
}

int rarvm_disassemble(Bitbuf *b, char *str) {
	int n = 0;
	*str = 0;
	if (bitget (b, n++)) {
		int opnum = bitnum (b, n, 5)+8;
		//int flags = opcodes[opnum].flags;
		const char *opstr = opcode_str (opnum);
		n += 5;
		// printf ("opnum %d\n", opnum);
		if (opstr) {
			printf ("%s", opstr);
		} else return 0;
		// XXX DUP
		if (opcodes[opnum].flags & 1) {
			printf (" ");
			n += disassemble_arg (b, n);
		}
		if (opcodes[opnum].flags & 2) {
			printf (", ");
			n += disassemble_arg (b, n);
		}
	} else {
		/* opnum >= 0 && <= 7 */
		int opnum = bitnum (b, n, 3);
		const char *opstr = opcode_str (opnum);
		n+= 3;
		if (opstr) {
			int byte_mode = bitget (b, n++);
			printf ("%s", opstr);
			if (byte_mode) {
				eprintf ("unsupported byte mode\n");
			} else {
				if (opcodes[opnum].flags & 1) {
					printf (" ");
					n += disassemble_arg (b, n);
				}
				if (opcodes[opnum].flags & 2) {
					printf (", ");
					n += disassemble_arg (b, n);
				}
			}
			printf ("\n"); //%s (%d) n=%d\n", opstr, opnum, n);
		}
	}
	return n;
}
