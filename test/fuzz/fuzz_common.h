#ifndef R2_TEST_FUZZ_COMMON_H
#define R2_TEST_FUZZ_COMMON_H

#include <r_util.h>

typedef struct {
	const ut8 *data;
	size_t len;
	size_t off;
} RFuzzInput;

static inline void rfuzz_input_init(RFuzzInput *input, const ut8 *data, size_t len) {
	input->data = data;
	input->len = len;
	input->off = 0;
}

static inline size_t rfuzz_remaining(const RFuzzInput *input) {
	return input->off < input->len? input->len - input->off: 0;
}

static inline ut8 rfuzz_consume_u8(RFuzzInput *input) {
	if (!rfuzz_remaining (input)) {
		return 0;
	}
	return input->data[input->off++];
}

static inline bool rfuzz_consume_bool(RFuzzInput *input) {
	return (rfuzz_consume_u8 (input) & 1) != 0;
}

static inline const ut8 *rfuzz_consume_bytes(RFuzzInput *input, size_t max_len, size_t *out_len) {
	size_t remaining = rfuzz_remaining (input);
	if (!remaining) {
		*out_len = 0;
		return NULL;
	}
	size_t limit = max_len && max_len < remaining? max_len: remaining;
	size_t chunk_len = limit;
	if (remaining > 1) {
		ut8 selector = rfuzz_consume_u8 (input);
		remaining = rfuzz_remaining (input);
		limit = max_len && max_len < remaining? max_len: remaining;
		chunk_len = limit? (selector % (limit + 1)): 0;
	}
	if (chunk_len > rfuzz_remaining (input)) {
		chunk_len = rfuzz_remaining (input);
	}
	const ut8 *chunk = input->data + input->off;
	input->off += chunk_len;
	*out_len = chunk_len;
	return chunk;
}

static inline const ut8 *rfuzz_consume_tail(RFuzzInput *input, size_t *out_len) {
	const ut8 *chunk = input->data + input->off;
	*out_len = rfuzz_remaining (input);
	input->off = input->len;
	return *out_len? chunk: NULL;
}

static inline char *rfuzz_strndup(const ut8 *data, size_t len) {
	if (len > ST32_MAX) {
		return NULL;
	}
	return r_str_newlen ((const char *)data, (int)len);
}

static inline char *rfuzz_consume_string(RFuzzInput *input, size_t max_len, size_t *out_len) {
	const ut8 *chunk = rfuzz_consume_bytes (input, max_len, out_len);
	return chunk? rfuzz_strndup (chunk, *out_len): strdup ("");
}

static inline void rfuzz_normalize_text(char *text, size_t len, char replacement) {
	size_t i;
	if (!text) {
		return;
	}
	for (i = 0; i < len; i++) {
		if (!text[i]) {
			text[i] = replacement;
		}
	}
}

#endif
