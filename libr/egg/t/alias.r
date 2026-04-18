/* register aliases via @alias
 *
 * `name@alias(value)` declares that any later reference to
 * `.name` should resolve to `value`. This lets you give
 * target registers meaningful names without changing the backend.
 *
 *   ragg2 -a esil -s t/alias.r
 *   ragg2 -a x86 -b 64 -s t/alias.r
 */

counter@alias(rax)
limit@alias(rcx)

main@global(16, 0) {
	.counter = 0;
	.limit = 10;
	.counter = .limit - 1;
	.counter += 1;
}
