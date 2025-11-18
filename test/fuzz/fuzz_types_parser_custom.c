#include <r_types.h>
#include <r_util.h>
#include <r_anal.h>
#include <string.h>
#include <stdlib.h>

// C-specific mutation strategies
static const char *c_types[] = {
	"int", "char", "short", "long", "float", "double", "void", "unsigned", "signed"
};

static const char *c_qualifiers[] = {
	"const", "volatile", "static", "extern", "inline"
};

// Replace a word with another C type/keyword
static void mutate_replace_word(char *data, size_t size) {
	if (!data || size < 3) {
		return;
	}

	// Find word boundaries
	size_t i = rand () % (size - 2);
	while (i < size - 2 && ! ((data[i] >= 'a' && data[i] <= 'z') || (data[i] >= 'A' && data[i] <= 'Z'))) {
		i++;
		if (i >= size - 2) {
			return;
		}
	}

	size_t word_start = i;
	while (i < size && ((data[i] >= 'a' && data[i] <= 'z') || (data[i] >= 'A' && data[i] <= 'Z') || data[i] == '_')) {
		i++;
	}
	size_t word_end = i;

	if (word_end > word_start) {
		// Replace with a C type
		const char *replacement = c_types[rand () % (sizeof (c_types) / sizeof (c_types[0]))];
		size_t repl_len = strlen (replacement);

		if (repl_len <= (word_end - word_start)) {
			memcpy (data + word_start, replacement, repl_len);
		}
	}
}

// Insert a C qualifier
static void mutate_insert_qualifier(char *data, size_t size) {
	if (!data || size < 10) {
		return;
	}

	size_t pos = rand () % (size - 9);
	const char *qualifier = c_qualifiers[rand () % (sizeof (c_qualifiers) / sizeof (c_qualifiers[0]))];
	size_t qual_len = strlen (qualifier);

	// Make room for qualifier
	if (pos + qual_len + 1 < size) {
		memmove (data + pos + qual_len, data + pos, size - pos - qual_len);
		memcpy (data + pos, qualifier, qual_len);
		data[pos + qual_len] = ' '; // Add space after qualifier
	}
}

// Modify numbers in the code
static void mutate_numbers(char *data, size_t size) {
	if (!data || size < 1) {
		return;
	}

	for (size_t i = 0; i < size - 1; i++) {
		if (data[i] >= '0' && data[i] <= '9') {
			// Replace digit with random digit
			data[i] = '0' + (rand () % 10);
		}
	}
}

// Modify brackets and braces
static void mutate_brackets(char *data, size_t size) {
	if (!data || size < 1) {
		return;
	}

	for (size_t i = 0; i < size; i++) {
		if (data[i] == '{' || data[i] == '}' || data[i] == '(' || data[i] == ')' ||
			data[i] == '[' || data[i] == ']') {
			// Randomly change bracket type
			char brackets[] = "{}()[]";
			data[i] = brackets[rand () % 6];
		}
	}
}

// Add/remove semicolons
static void mutate_semicolons(char *data, size_t size) {
	if (!data || size < 2) {
		return;
	}

	for (size_t i = 0; i < size - 1; i++) {
		if (data[i] == ';' && (rand () % 3) == 0) {
			// Remove semicolon
			memmove (data + i, data + i + 1, size - i - 1);
			data[size - 1] = '\0';
		} else if (data[i] == '\n' && (rand () % 5) == 0 && i < size - 2) {
			// Add semicolon before newline
			memmove (data + i + 1, data + i, size - i - 1);
			data[i] = ';';
			data[i + 1] = '\n';
		}
	}
}

// Custom mutator entry point
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
	if (!data || size == 0 || max_size < 3) {
		return 0;
	}

	srand (seed);

	// Choose mutation strategy
	int mutation_type = rand () % 6;

	switch (mutation_type) {
	case 0:
		mutate_replace_word ((char *)data, size);
		break;
	case 1:
		mutate_insert_qualifier ((char *)data, size);
		break;
	case 2:
		mutate_numbers ((char *)data, size);
		break;
	case 3:
		mutate_brackets ((char *)data, size);
		break;
	case 4:
		mutate_semicolons ((char *)data, size);
		break;
	case 5:
		// Combine multiple mutations
		mutate_numbers ((char *)data, size);
		mutate_replace_word ((char *)data, size);
		break;
	}

	// Ensure null termination if there's space
	if (size < max_size) {
		data[size] = '\0';
	}

	return size;
}

// Custom crossover
size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
	const uint8_t *data2, size_t size2,
	uint8_t *out, size_t max_out_size,
	unsigned int seed) {
	if (!data1 || !data2 || size1 == 0 || size2 == 0 || max_out_size < 3) {
		return 0;
	}

	srand (seed);

	// Take first half from data1, second half from data2
	size_t split1 = size1 / 2;
	size_t split2 = size2 / 2;

	size_t new_size = split1 + (size2 - split2);
	if (new_size > max_out_size) {
		new_size = max_out_size;
	}

	// Copy first part from data1
	memcpy (out, data1, split1 < new_size? split1: new_size);

	// Copy second part from data2
	if (new_size > split1) {
		memcpy (out + split1, data2 + split2, new_size - split1);
	}

	// Ensure null termination
	if (new_size < max_out_size) {
		out[new_size] = '\0';
	}

	return new_size;
}

int LLVMFuzzerInitialize(int *lf_argc, char ***lf_argv) {
	r_log_set_quiet (true);
	return 0;
}

int LLVMFuzzerTestOneInput(const ut8 *data, size_t len) {
	if (len < 1) {
		return 0;
	}

	// Ensure null-terminated string for the parser
	char *input = r_str_ndup ((const char *)data, len);
	if (!input) {
		return 0;
	}

	char *errmsg = NULL;
	char *result = r_anal_cparse (NULL, (const char *)input, &errmsg);

	// Clean up
	free (input);
	free (result);
	free (errmsg);

	return 0;
}