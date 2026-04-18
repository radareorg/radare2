/* conditionals: if/else and while
 *
 *   ragg2 -a esil -s t/cond.r
 *   ragg2 -a x86 -b 64 -s t/cond.r
 *
 * The ESIL backend emits:
 *   - "X,a1,OP,?{,__end,PC,:=,}" for ordered comparisons
 *   - "X,a1,==,$z,!,?{,__end,PC,:=,}" for equality tests
 * so that the body is skipped when the condition is false.
 *
 * While loops additionally re-push the condition variable into a1
 * at the bottom of the body and unconditionally jump back to the
 * begin label, where the same check re-runs.
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

	/* countdown loop: keep looping while .var0 > 0 */
	.var0 = 3;
	while (.var0) {
		.var0 -= 1;
	}
}
