/*
mov r0, #33

  .-- select  3 bit opcode mode
  |  .---- op|ode number (mov)
  v  v  .- BYTEMODE (wtf)
  0 000 0 1 000 00 11 (32bits)
   reg ---^  |  |   ^--- 32bit integer
   regnum ---'  `------- inmediate mark

opcode encoding
===============
0>=

arg encoding
============
reg   1    x3
memr  01 0 x3
memi  01 11 11 x32
memri 01 10 r3 11 x32
imm   0011 x32
*/
static int assemble_arg(Bitbuf *b, char *a) {
	printf ("A = (%s)\n", a);
	int r;
	if (!a)
		return 1;
	r = getreg (a);
	if (r != -1) {
		bitadd (b, 1, 1);
		bitadd (b, r, 3);
		return 1;
	} else 
	if (*a == '[') {
		char *sign = strchr (++a, '+');
		if (!sign) sign = strchr (a, '-');
		bitadd (b, 0, 1);
		bitadd (b, 1, 1);
		if (sign) {
			// XXX: atm only basereg + idx
			int n, r = getreg (a);
			n = strtoul (sign+1, NULL, 0);
			bitadd (b, 1, 1);
			bitadd (b, 0, 1);
			bitadd (b, r, 3);
			bitadd (b, 3, 2);
			if (*sign == '-')
				n = -n;
			bitadd (b, n, 32);
		} else {
			// XXX only reg or num
			bitadd (b, 0, 1);
			if (*a == '#') a++; // XXX
			r = getreg (a);
			if (r!=-1) {
				bitadd (b, 0, 1);
				bitadd (b, r, 3);
			} else {
				unsigned int n;
				if (*a=='#') a++;
				n = strtoul (a, NULL, 0);
				bitadd (b, 1, 1);
				bitadd (b, 1, 1);
				bitadd (b, 3, 2);
				bitadd (b, n, 32);
			}
		}
		return 1;
	} else {
		unsigned int n = strtoul (a+1, NULL, 0);
		// inmediate
printf ("n=%d (%s)\n", n, a);
		bitadd (b, 0, 2);
		// 0 = 4 bit
		// 1 = 8/12 bit (???
		// 2 = 16 bit
		// 3 = 32 bit
		bitadd (b, 3, 2);
		bitadd (b, n, 32);
		return 1;
	}
	return 0;
}

int rarvm_assemble (Bitbuf *b, const char *c) {
	char* arg0 = NULL;
	char* arg1 = NULL;
	int opnum;
	char *p, *str = strdup (skipspaces (c));
	p = strchr (str, ' ');
	if (p) {
		*p = 0;
		arg0 = p+1;
		SKIPSPACES (arg0);
		arg1 = strchr (arg0, ',');
		if (arg1)
			*arg1++ = 0;
	}
	opnum = opcode_num (str);
	if (opnum>=0 && opnum<=7) {
		bitadd (b, 0, 1);
		bitadd (b, opnum, 3);
	} else
	if (opnum>=8 && opnum<=39) {
		bitadd (b, 1, 1);
		bitadd (b, opnum+24, 5);
	} else {
		free (str);
		fprintf (stderr, "Oops. unsupported opcode\n");
		return 0;
	}

	if (1 && opcodes[opnum].flags & T_BYTE) {
		bitadd (b, 0, 1);
	}

	if (opcodes[opnum].flags & 1) {
		SKIPSPACES (arg0);
		if (!assemble_arg (b, arg0)) {
                        free (str);
			return 0;
                }
		if (opcodes[opnum].flags & 2) {
			SKIPSPACES (arg1);
			if (!assemble_arg (b, arg1))
				return 0;
		}
	}
	free (str);
	return b->bits;
}
