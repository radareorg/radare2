/* direct native-register access
 *
 * Any unrecognised `.name` is emitted verbatim as a register or
 * symbol name. This lets the high-level language drive target
 * specific registers (particularly useful with `-a esil`, where
 * abstract ESIL registers can be named freely).
 *
 * Compile for example with:
 *   ragg2 -a esil -s t/regs.r
 *   ragg2 -a x86 -b 64 -s t/regs.r
 */

main@global(16, 0) {
	.rax = 1;              /* write constant into rax */
	.rcx = .rax;           /* copy rax into rcx */
	.rdx = .rax + 41;      /* rax + 41 -> rdx */
	.rax = .rdx * 2;       /* rax = rdx * 2 */
}
