/* arithmetic expressions and operator precedence
 *
 * try compiling with `ragg2 -a esil -s t/arith.r` to see
 * how each expression becomes a sequence of ESIL tokens. */

main@global(32, 0) {
	.var0 = 5 + 3;          /* 8 */
	.var4 = 10 - 4;         /* 6 */
	.var8 = 2 + 3 * 4;      /* precedence: 2 + 12 */
	.var12 = 1 | 2 | 4;     /* bitwise or chain */
	.var16 = 0xff & 0x0f;   /* bitwise and */
	.var20 = 7 ^ 3;         /* xor */

	/* compound operators */
	.var24 = 10;
	.var24 += 5;
	.var24 *= 2;
}
