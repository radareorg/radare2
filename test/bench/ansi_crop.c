#include <r_util.h>
#include <r_lib.h>

typedef char *(*Crop)(const char *, ut32, ut32, ut32, ut32);

typedef struct {
	const char *name;
	const char *line;
	int rows;
	ut32 x, y, x2, y2;
} CropCase;

static double measure(Crop crop, const char *input, const CropCase *c, int iterations) {
	ut64 start = r_time_now_mono ();
	int i;
	for (i = 0; i < iterations; i++) {
		char *output = crop (input, c->x, c->y, c->x2, c->y2);
		if (!output) {
			exit (1);
		}
		free (output);
	}
	return (r_time_now_mono () - start) * 1000.0 / iterations;
}

static int compare_time(const void *a, const void *b) {
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf (stderr, "Usage: %s before-library after-library\n", argv[0]);
		return 1;
	}
	void *libraries[2] = { NULL, NULL };
	Crop crops[2];
	int i;
	for (i = 0; i < 2; i++) {
		libraries[i] = r_lib_dl_open (argv[i + 1], false);
		crops[i] = libraries[i]? (Crop)r_lib_dl_sym (libraries[i], "r_str_ansi_crop"): NULL;
		if (!crops[i]) {
			fprintf (stderr, "Cannot load r_str_ansi_crop from %s\n", argv[i + 1]);
			return 1;
		}
	}
	if (crops[0] == crops[1]) {
		fprintf (stderr, "Both paths resolve to the same function\n");
		return 1;
	}
	const char *plain = "0x00001000  4889e5          mov rbp, rsp ; function prologue and stack frame setup\n";
	const char *ansi = "\x1b[32m0x00001000\x1b[0m  \x1b[33m4889e5\x1b[0m          \x1b[36mmov\x1b[0m rbp, rsp ; function prologue and stack frame setup\n";
	CropCase cases[] = {
		{ "empty", "", 1, 0, 0, 20, 1 },
		{ "ascii-short", "abc", 1, 0, 0, 20, 1 },
		{ "ascii-title", "radare2 panel title: disassembly", 1, 0, 0, 20, 1 },
		{ "ansi-title", "\x1b[38;2;200;100;50mradare2 panel title: disassembly\x1b[0m", 1, 0, 0, 20, 1 },
		{ "ascii-panel", plain, 40, 0, 0, 60, 25 },
		{ "ansi-panel", ansi, 40, 0, 0, 60, 25 },
		{ "ansi-offset", ansi, 40, 16, 10, 60, 35 },
		{ "ascii-uncropped", plain, 40, 0, 0, UT32_MAX, UT32_MAX },
		{ "utf8-panel", "│ café 世界 ── 日本語 ── résumé │ café 世界 ── 日本語 ── résumé │\n", 40, 3, 0, 35, 25 },
		{ "ansi-dense", "\x1b[31ma\x1b[32mb\x1b[33mc\x1b[34md\x1b[35me\x1b[36mf\x1b[0m\n", 40, 0, 0, 6, 25 },
		{ "long-line", "0123456789abcdef", 65536, 0, 0, 80, 1 },
		{ "large-top", ansi, 10000, 0, 0, 60, 25 },
		{ "large-bottom", ansi, 10000, 0, 9975, 60, 10000 },
	};
	puts ("case,input_bytes,iterations,before_ns,after_ns,speedup");
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		const CropCase *c = &cases[i];
		char *input = r_str_repeat (c->line, c->rows);
		if (!input) {
			return 1;
		}
		char *before = crops[0] (input, c->x, c->y, c->x2, c->y2);
		char *after = crops[1] (input, c->x, c->y, c->x2, c->y2);
		if (!before || !after || strcmp (before, after)) {
			fprintf (stderr, "Output mismatch: %s\n", c->name);
			return 1;
		}
		free (before);
		free (after);
		int iterations = 100;
		double estimate = measure (crops[0], input, c, iterations);
		iterations = (int)R_CLAMP (20000000.0 / R_MAX (estimate, 1), 100, 1000000);
		double times[2][7];
		int trial, order;
		for (trial = 0; trial < 7; trial++) {
			for (order = 0; order < 2; order++) {
				int variant = (trial + order) % 2;
				times[variant][trial] = measure (crops[variant], input, c, iterations);
			}
		}
		qsort (times[0], 7, sizeof (double), compare_time);
		qsort (times[1], 7, sizeof (double), compare_time);
		printf ("%s,%zu,%d,%.1f,%.1f,%.2f\n", c->name, strlen (input), iterations,
			times[0][3], times[1][3], times[0][3] / times[1][3]);
		free (input);
	}
	for (i = 0; i < 2; i++) {
		r_lib_dl_close (libraries[i]);
	}
	return 0;
}
