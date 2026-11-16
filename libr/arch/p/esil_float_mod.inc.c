/* radare2 - LGPL - Copyright 2026 - pancake, gemesa */

#ifndef R_ARCH_ESIL_FLOAT_MOD_PURE
// Set to 1 to compare the pure ESIL implementation with F%.
#define R_ARCH_ESIL_FLOAT_MOD_PURE 0
#endif

static void esil_float_mod(RStrBuf *esil, const char *dividend, const char *divisor) {
#if R_ARCH_ESIL_FLOAT_MOD_PURE
	r_strbuf_setf (esil,
		"%s,NAN,%s,NAN,|,0x7ff0000000000000,0x7fffffffffffffff,%s,&,F==,|,0,%s,F==,|,"
		"?{,0x7ff8000000000000,}{,0x7ff0000000000000,0x7fffffffffffffff,%s,&,F==,0,%s,F==,|,?{,%s,}{,"
		"0x7fffffffffffffff,%s,&,",
		dividend, divisor, dividend, divisor, divisor, dividend, dividend, dividend);
	size_t loop = r_str_char_count (r_strbuf_get (esil), ',');
	r_strbuf_appendf (esil, "DUP,0x7fffffffffffffff,%s,&,F<=,?{,", divisor);
	// Scale the divisor to keep the quotient finite and exactly representable.
	r_strbuf_appendf (esil,
		"DUP,LOG2,FLOOR,0x7fffffffffffffff,%s,&,LOG2,FLOOR,SWAP,F-,0x4040000000000000,SWAP,F-,"
		"DUP,0,SWAP,F<,?{,POP,0,},0x7fffffffffffffff,%s,&,FSCALE,DUP,ROT,DUP,ROT,DUP,ROT,F/,FLOOR,-F,F*+,"
		// Fused subtraction avoids cancellation; correct a quotient rounded up by division.
		"DUP,0,SWAP,F<,?{,F+,}{,SWAP,POP,},%zu,GOTO,},"
		"0x8000000000000000,%s,&,|,},}",
		divisor, divisor, loop, dividend);
#else
	r_strbuf_setf (esil, "%s,%s,F%%", divisor, dividend);
#endif
}
