#include <r_types.h>
#include <r_util.h>
#include <r_anal.h>
#include <string.h>
#include <stdlib.h>

#include "fuzz_common.h"

extern size_t LLVMFuzzerMutate(ut8 *data, size_t size, size_t max_size);

static const char *c_types[] = {
	"int", "char", "short", "long", "float", "double", "void", "unsigned", "signed"
};

static const char *c_qualifiers[] = {
	"const", "volatile", "static", "extern", "inline"
};

static const char *c_fragments[] = {
	"typedef struct Foo { int x; } Foo;\n",
	"enum Foo { FOO_ZERO = 0, FOO_ONE = 1 };\n",
	"union Foo { int i; char c; long long ll; };\n",
	"int (*handler)(const char *name, void *user);\n",
	"struct Foo { unsigned a:1; unsigned b:7; };\n",
	"const char *names[4] = {\"a\", \"b\", \"c\", \"d\"};\n",
};

static void mutate_replace_word(char *data, size_t size) {
	size_t i;
	if (!data || size < 3) {
		return;
	}
	i = rand () % (size - 2);
	while (i < size - 2 && !((data[i] >= 'a' && data[i] <= 'z')
			|| (data[i] >= 'A' && data[i] <= 'Z'))) {
		i++;
	}
	if (i >= size - 2) {
		return;
	}
	size_t word_start = i;
	while (i < size && ((data[i] >= 'a' && data[i] <= 'z')
			|| (data[i] >= 'A' && data[i] <= 'Z') || data[i] == '_')) {
		i++;
	}
	size_t word_end = i;
	if (word_end > word_start) {
		const char *replacement = c_types[rand () % (sizeof (c_types) / sizeof (c_types[0]))];
		size_t repl_len = strlen (replacement);
		if (repl_len <= (word_end - word_start)) {
			memcpy (data + word_start, replacement, repl_len);
		}
	}
}

static size_t mutate_insert_qualifier(char *data, size_t size, size_t max_size) {
	const char *qualifier;
	size_t qual_len;
	size_t needed;
	size_t pos;
	if (!data || size < 2) {
		return size;
	}
	qualifier = c_qualifiers[rand () % (sizeof (c_qualifiers) / sizeof (c_qualifiers[0]))];
	qual_len = strlen (qualifier);
	needed = qual_len + 1;
	if (needed > max_size - size) {
		return size;
	}
	pos = rand () % (size + 1);
	memmove (data + pos + needed, data + pos, size - pos);
	memcpy (data + pos, qualifier, qual_len);
	data[pos + qual_len] = ' ';
	return size + needed;
}

static void mutate_numbers(char *data, size_t size) {
	size_t i;
	if (!data || size < 1) {
		return;
	}
	for (i = 0; i < size; i++) {
		if (data[i] >= '0' && data[i] <= '9') {
			data[i] = '0' + (rand () % 10);
		}
	}
}

static void mutate_brackets(char *data, size_t size) {
	size_t i;
	if (!data || size < 1) {
		return;
	}
	for (i = 0; i < size; i++) {
		if (data[i] == '{' || data[i] == '}' || data[i] == '(' || data[i] == ')'
				|| data[i] == '[' || data[i] == ']') {
			static const char brackets[] = "{}()[]";
			data[i] = brackets[rand () % (sizeof (brackets) - 1)];
		}
	}
}

static void mutate_semicolons(char *data, size_t size) {
	size_t i;
	if (!data || size < 2) {
		return;
	}
	for (i = 0; i < size - 1; i++) {
		if (data[i] == ';' && !(rand () % 3)) {
			memmove (data + i, data + i + 1, size - i - 1);
			data[size - 1] = '\0';
		} else if (data[i] == '\n' && !(rand () % 5) && i < size - 2) {
			memmove (data + i + 1, data + i, size - i - 1);
			data[i] = ';';
			data[i + 1] = '\n';
		}
	}
}

static size_t mutate_insert_fragment(char *data, size_t size, size_t max_size) {
	const char *fragment;
	size_t frag_len;
	size_t pos;
	if (!data || size >= max_size) {
		return size;
	}
	fragment = c_fragments[rand () % (sizeof (c_fragments) / sizeof (c_fragments[0]))];
	frag_len = strlen (fragment);
	if (!frag_len) {
		return size;
	}
	if (frag_len > max_size - size) {
		frag_len = max_size - size;
	}
	pos = rand () % (size + 1);
	memmove (data + pos + frag_len, data + pos, size - pos);
	memcpy (data + pos, fragment, frag_len);
	return size + frag_len;
}

static size_t mutate_duplicate_statement(char *data, size_t size, size_t max_size) {
	size_t start;
	size_t end;
	size_t stmt_len;
	size_t i;
	if (!data || size < 4 || size >= max_size) {
		return size;
	}
	start = rand () % size;
	for (i = start; i > 0; i--) {
		if (data[i - 1] == '\n' || data[i - 1] == ';' || data[i - 1] == '{') {
			break;
		}
	}
	start = i;
	end = start;
	while (end < size) {
		if (data[end] == '\n' || data[end] == ';' || data[end] == '}') {
			end++;
			break;
		}
		end++;
	}
	if (end <= start) {
		return size;
	}
	stmt_len = end - start;
	if (stmt_len > max_size - size) {
		stmt_len = max_size - size;
	}
	if (!stmt_len) {
		return size;
	}
	memmove (data + end + stmt_len, data + end, size - end);
	memcpy (data + end, data + start, stmt_len);
	return size + stmt_len;
}

size_t LLVMFuzzerCustomMutator(ut8 *data, size_t size, size_t max_size, unsigned int seed) {
	int mutation_type;
	if (!data || !size || max_size < 3) {
		return 0;
	}
	srand (seed);
	if (size > 1 && (rand () & 1)) {
		size = LLVMFuzzerMutate (data, size, max_size);
	}
	mutation_type = rand () % 8;
	switch (mutation_type) {
	case 0:
		mutate_replace_word ((char *)data, size);
		break;
	case 1:
		size = mutate_insert_qualifier ((char *)data, size, max_size);
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
		size = mutate_insert_fragment ((char *)data, size, max_size);
		break;
	case 6:
		size = mutate_duplicate_statement ((char *)data, size, max_size);
		break;
	case 7:
		mutate_replace_word ((char *)data, size);
		mutate_numbers ((char *)data, size);
		break;
	}
	if (size < max_size) {
		data[size] = '\0';
	}
	return size;
}

size_t LLVMFuzzerCustomCrossOver(const ut8 *data1, size_t size1,
	const ut8 *data2, size_t size2, ut8 *out, size_t max_out_size, unsigned int seed) {
	size_t split1;
	size_t split2;
	size_t new_size;
	size_t i;
	if (!data1 || !data2 || !size1 || !size2 || max_out_size < 3) {
		return 0;
	}
	srand (seed);
	split1 = rand () % size1;
	split2 = rand () % size2;
	for (i = split1; i < size1; i++) {
		if (data1[i] == '\n' || data1[i] == ';') {
			split1 = i + 1;
			break;
		}
	}
	for (i = split2; i < size2; i++) {
		if (data2[i] == '\n' || data2[i] == ';') {
			split2 = i;
			break;
		}
	}
	new_size = split1 + (size2 - split2);
	if (new_size > max_out_size) {
		new_size = max_out_size;
	}
	memcpy (out, data1, split1 < new_size? split1: new_size);
	if (new_size > split1) {
		memcpy (out + split1, data2 + split2, new_size - split1);
	}
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
	char *input = rfuzz_strndup (data, len);
	if (!input) {
		return 0;
	}
	rfuzz_normalize_text (input, len, ' ');

	RAnal *anal = r_anal_new ();
	char *errmsg = NULL;
	char *result = r_anal_cparse (anal, (const char *)input, &errmsg);
	if (anal && result) {
		r_anal_save_parsed_type (anal, result);
	}
	free (input);
	free (result);
	free (errmsg);
	r_anal_free (anal);
	return 0;
}
