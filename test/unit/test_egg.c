#define _GNU_SOURCE
#include <sys/mman.h>
#include <string.h>
#include <r_egg.h>
#include "minunit.h" 

#if __linux__ && __x86_64__
const char *arch = R_SYS_ARCH;
const char *os = R_EGG_OS_NAME;
const int bits = (R_SYS_BITS & R_SYS_BITS_64)? 64: 32;
const char program[] = "                \
read@syscall(0);                        \
write@syscall(1);                       \
open@syscall(2);                        \
exit@syscall(60);                       \
main@global(2000, 6) {			\
.var17 = open(\"./file\", 2);		\
.var25 = read(.var17, &.var33, 2000);	\
write(1, &.var33, .var25);		\
exit(0);				\
}                                       \
";


bool test_r_egg_save(void) {
	REgg *egg = r_egg_new ();
	RAnal *a = r_anal_new ();
	r_anal_bind (a, &egg->rasm->analb);

	r_egg_setup (egg, arch, bits, 0, os);
	r_egg_load (egg, program, 0);

	mu_assert ("Compilation", r_egg_compile (egg)); 
	mu_assert ("Assembly", r_egg_assemble (egg)); 
	mu_assert ("Binary", r_egg_get_bin (egg));

	r_egg_finalize (egg); 

	int out = memfd_create ("out", 0);
	/* TODO use tempfile */ 
	int in = open ("./file", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR); 
	write (in, "test file", 9);
	close (in); 

	if (!fork ()) {
		dup2 (out, STDOUT_FILENO);
		r_egg_run (egg);
	}

	wait (NULL);

	struct stat sz; 
	fstat (out, &sz);
	char buf[sz.st_size + 1];

	lseek (out, 0, 0);
	read (out, buf, sz.st_size);

	buf[sz.st_size] = '\0';

	mu_assert_eq (strcmp (buf, "test file"), 0, "Save");

	close (out);
	unlink ("./file");
	r_egg_free (egg);
	
	mu_end;
}
#else
bool test_r_egg_save(void) {
	R_LOG_WARN ("This test is linux specific because it's using memfd");
	mu_end;
}
#endif

bool all_tests(void) {
	mu_run_test (test_r_egg_save);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
