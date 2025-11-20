#include <r_core.h>

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Usage: %s <binary>\n", argv[0]);
		return 1;
	}

	RCore *core = r_core_new();
	if (!core) {
		printf("Failed to create core\n");
		return 1;
	}

	// Load the binary
	if (!r_core_file_open(core, argv[1], 0, 0)) {
		printf("Failed to open file: %s\n", argv[1]);
		r_core_free(core);
		return 1;
	}

	// Analyze the binary
	r_core_cmd0(core, "aa");

	// Test vmatrix function
	printf("Testing vmatrix functionality...\n");
	r_core_visual_matrix(core);
	printf("Vmatrix test completed\n");

	r_core_free(core);
	return 0;
}