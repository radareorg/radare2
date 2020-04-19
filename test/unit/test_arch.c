#include <r_arch.h>
#include "minunit.h"

int all_tests() {
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
