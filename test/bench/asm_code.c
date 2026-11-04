#include <r_asm.h>

static bool bench_equ(int count) {
	RAsmCode *code = r_asm_code_new ();
	int i;
	for (i = 0; i < count; i++) {
		char name[64];
		snprintf (name, sizeof (name), "unused_%d", i);
		r_asm_code_set_equ (code, name, "0x5678");
	}
	r_asm_code_set_equ (code, "target", "0x1234");
	char *str = r_asm_code_equ_replace (code, "ld hl, target+4");
	bool valid = str && !strcmp (str, "ld hl, 0x1234+4");
	free (str);
	if (valid) {
		ut64 start = r_time_now_mono ();
		for (i = 0; i < 4096; i++) {
			str = r_asm_code_equ_replace (code, "ld hl, target+4");
			if (!str) {
				valid = false;
				break;
			}
			free (str);
		}
		printf ("equ,%d,4096,%"PFMT64u"\n", count, r_time_now_mono () - start);
	}
	r_asm_code_free (code);
	return valid;
}

static bool bench_lines(int count) {
	RStrBuf source = {0};
	int i;
	for (i = 0; i < count; i++) {
		if (!r_strbuf_append (&source, ".byte 0\n")) {
			r_strbuf_fini (&source);
			return false;
		}
	}
	RAsm *a = r_asm_new ();
	ut64 start = r_time_now_mono ();
	RAsmCode *code = r_asm_assemble (a, r_strbuf_get (&source));
	ut64 elapsed = r_time_now_mono () - start;
	bool valid = code && code->len == count;
	if (valid) {
		for (i = 0; i < code->len; i++) {
			if (code->bytes[i]) {
				valid = false;
				break;
			}
		}
	}
	printf ("lines,%d,1,%"PFMT64u"\n", count, elapsed);
	r_asm_code_free (code);
	r_asm_free (a);
	r_strbuf_fini (&source);
	return valid;
}

int main(int argc, char **argv) {
	const int symbols[] = { 0, 128, 1024, 8192 };
	const int lines[] = { 4096, 16384, 65536 };
	puts ("case,count,iterations,total_us");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (symbols); i++) {
		if (!bench_equ (symbols[i])) {
			return 1;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (lines); i++) {
		if (!bench_lines (lines[i])) {
			return 1;
		}
	}
	return 0;
}
