/* direct native-register access
 *
 * The `.%name` form copies the name verbatim into the instruction
 * stream. This is the unambiguous way to target a concrete register,
 * as opposed to `.varN` (frame slot), `.regN` (indexed gpr), or
 * user-defined aliases.
 *
 *   ragg2 -a esil -s t/regs.r
 *   ragg2 -a x86 -b 64 -s t/regs.r
 */

main@global(16, 0) {
	.%rax = 1;                  /* write constant into rax */
	.%rcx = .%rax;              /* copy rax into rcx */
	.%rdx = .%rax + 41;         /* rax + 41 -> rdx */
	.%rax = .%rdx * 2;          /* rax = rdx * 2 */
}
