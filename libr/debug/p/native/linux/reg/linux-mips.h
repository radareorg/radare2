// XXX wtf
#if 0
	reg      name    usage
	---+-----------+-------------
	0        zero   always zero
	1         at    reserved for assembler
	2-3     v0-v1   expression evaluation, result of function
	4-7     a0-a3   arguments for functions
	8-15    t0-t7   temporary (not preserved across calls)
	16-23   s0-s7   saved temporary (preserved across calls)
	24-25   t8-t9   temporary (not preserved across calls)
	26-27   k0-k1   reserved for OS kernel
	28      gp      points to global area
	29      sp      stack pointer
	30      fp      frame pointer
	31      ra      return address
#if 0
16 /* 0 - 31 are integer registers, 32 - 63 are fp registers.  */
PC = 272
17 #define FPR_BASE        32
18 #define PC              64
19 #define CAUSE           65
20 #define BADVADDR        66
21 #define MMHI            67
22 #define MMLO            68
23 #define FPC_CSR         69
24 #define FPC_EIR         70
#endif

#endif

/* IMPORTANT - MIPS ptrace always returns the registers in 64bits format,
   so this register table has been modified from 64 bits to 32 bits.
   Example:
	Originals (64 bits):
	  "gpr    at      .64     8       0\n"
	  "gpr    v0      .64     16      0\n"
	Modified to (32 bits):
          "gpr    at      .32     12      0\n"
          "gpr    v0      .32     20      0\n"

   It is using the same arena->size, but we are only using the last 4 bytes
   (LITTLE ENDIAN PROBLEMS?)
*/
	return strdup (
        "=PC    pc\n"
        "=SP    sp\n"
        "=BP    fp\n"
        "=A0    a0\n"
        "=A1    a1\n"
        "=A2    a2\n"
        "=A3    a3\n"
        "gpr    zero    .32     4       0\n"
        // XXX DUPPED CAUSES FAILURE "gpr       at      .32     8       0\n"
        "gpr    at      .32     12      0\n"
        "gpr    v0      .32     20      0\n"
        "gpr    v1      .32     28      0\n"
        /* args */
        "gpr    a0      .32     36      0\n"
        "gpr    a1      .32     44      0\n"
        "gpr    a2      .32     52      0\n"
        "gpr    a3      .32     60      0\n"
        /* tmp */
        "gpr    t0      .32     68      0\n"
        "gpr    t1      .32     76      0\n"
        "gpr    t2      .32     84      0\n"
        "gpr    t3      .32     92      0\n"
        "gpr    t4      .32     100     0\n"
        "gpr    t5      .32     108     0\n"
        "gpr    t6      .32     116     0\n"
        "gpr    t7      .32     124     0\n"
        /* saved */
        "gpr    s0      .32     132     0\n"
        "gpr    s1      .32     140     0\n"
        "gpr    s2      .32     148     0\n"
        "gpr    s3      .32     156     0\n"
        "gpr    s4      .32     164     0\n"
        "gpr    s5      .32     172     0\n"
        "gpr    s6      .32     180     0\n"
        "gpr    s7      .32     188     0\n"
	/* tmp */
        "gpr    t8      .32     196     0\n"
        "gpr    t9      .32     204     0\n"
        /* special */
        "gpr    k0      .32     212     0\n"
        "gpr    k1      .32     220     0\n"
        "gpr    gp      .32     228     0\n"
        "gpr    sp      .32     236     0\n"
        "gpr    fp      .32     244     0\n"
        "gpr    ra      .32     252     0\n"
        /* extra */
        "gpr    pc      .32     276     0\n"
	);
