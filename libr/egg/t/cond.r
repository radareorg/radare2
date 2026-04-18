/* conditionals: if and while
 *
 *   ragg2 -a esil -s t/cond.r
 *   ragg2 -a x86 -b 64 -s t/cond.r
 *
 * The ESIL backend compiles each function into a single expression
 * of comma-separated tokens. Labels are resolved at finalize time
 * into numeric word indices so the output is pure ESIL and can be
 * fed to r2's `ae` command:
 *
 *   - "X,a1,OP,?{,N,GOTO,}"        for ordered comparisons
 *   - "X,a1,==,$z,[!,]?{,N,GOTO,}" for equality tests
 *   - "N,GOTO"                     unconditional branch
 *
 * where N is the word position of the target inside the expression.
 *
 * While loops additionally refresh a1 from the loop variable at the
 * bottom of the body before jumping back to the begin position, so
 * the same comparison re-runs against the updated value.
 */

main@global(16, 0) {
	.var0 = 5;

	/* execute body only if .var0 == 0 */
	if (.var0 == 0) {
		.var0 = 99;
	}

	/* execute body only if .var0 != 0 */
	if (.var0 != 0) {
		.var0 = 42;
	}

	/* "truthy" form - body runs when .var0 is non-zero */
	if (.var0) {
		.var0 = 1;
	}

	/* countdown loop: keep looping while .var0 is non-zero */
	.var0 = 3;
	while (.var0) {
		.var0 -= 1;
	}
}
