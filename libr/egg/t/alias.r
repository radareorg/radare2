/* register aliases via @alias
 *
 * `name@alias(value)` declares that any later `.name` should
 * resolve to `value`. Useful for giving target registers
 * meaningful names without touching the backend, and for keeping
 * programs portable when the register set differs across arches.
 *
 *   ragg2 -a esil -s t/alias.r
 *   ragg2 -a x86 -b 64 -s t/alias.r
 *
 * An unknown `.name` is a compile error unless it is defined via
 * @alias or prefixed with `%` (see regs.r for the raw form).
 */

counter@alias(rax)
limit@alias(rcx)

main@global(16, 0) {
	.counter = 0;
	.limit = 10;
	.counter = .limit - 1;
	.counter += 1;
}
