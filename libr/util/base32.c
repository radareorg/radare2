/* radare - LGPL - Copyright 2024 - pancake */

#include <r_util/r_base32.h>

#if R2_USE_NEW_ABI
static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char base32_padding = '=';

// Utility function to find index in base32 alphabet
static int base32_char_index(char c) {
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= '2' && c <= '7') {
		return c - '2' + 26;
	}
	return -1;
}

R_API char *r_base32_encode(const ut8 *data, size_t input_length, size_t *output_length) {
	size_t encoded_size = (input_length + 4) / 5 * 8;
	char *encoded_data = (char *)malloc (encoded_size + 1);
	if (!encoded_data) {
		return NULL;
	}

	size_t i, j, index;
	int current_byte, next_byte;
	for (i = 0, j = 0; i < input_length;) {
		current_byte = data[i++] << 8;
		if (i < input_length) current_byte |= data[i++];
		current_byte <<= 8;
		if (i < input_length) current_byte |= data[i++];
		current_byte <<= 8;
		if (i < input_length) current_byte |= data[i++];
		current_byte <<= 8;
		if (i < input_length) current_byte |= data[i++];

		for (index = 0; index < 8; index++) {
			next_byte = (current_byte & 0xF8000000) >> 27;
			encoded_data[j++] = base32_alphabet[next_byte];
			current_byte <<= 5;
		}
	}

	while (j < encoded_size) {
		encoded_data[j++] = base32_padding;
	}
	encoded_data[encoded_size] = '\0';

	if (output_length) {
		*output_length = encoded_size;
	}
	return encoded_data;
}

R_API ut8 *r_base32_decode(const char *data, size_t input_length, size_t *output_length) {
	if (input_length % 8 != 0) {
		return NULL;
	}

	size_t decoded_size = input_length * 5 / 8;
	unsigned char *decoded_data = (unsigned char *)malloc (decoded_size);
	if (!decoded_data) {
		return NULL;
	}

	size_t i, j, index;
	int current_byte, next_byte;
	for (i = 0, j = 0; i < input_length;) {
		current_byte = 0;
		for (index = 0; index < 8 && i < input_length; index++) {
			next_byte = base32_char_index (toupper (data[i++]));
			if (next_byte == -1) {
				return NULL;
			}
			current_byte = (current_byte << 5) | next_byte;
		}

		for (index = 0; index < 5; index++) {
			decoded_data[j++] = (current_byte & 0xFF000000) >> 24;
			current_byte <<= 8;
		}
	}

	if (output_length) {
		*output_length = decoded_size;
	}
	return decoded_data;
}

R_API char *base32_encode_ut64(ut64 input) {
	size_t encoded_size = 13; // Maximum 13 characters for 64-bit input
	char *encoded_data = (char *)malloc (encoded_size + 1);
	if (!encoded_data) {
		return NULL;
	}

	int i;
	for (i = 12; i >= 0; i--) {
		encoded_data[i] = base32_alphabet[input & 0x1F];
		input >>= 5;
	}
	encoded_data[encoded_size] = '\0';

	return encoded_data;
}

// Decode function for ut64
R_API ut64 base32_decode_ut64(const char *input) {
	ut64 decoded_value = 0;
	int i;
	for (i = 0; i < 13; i++) {
		int index = base32_char_index (toupper (input[i]));
		if (index == -1) {
			return 0;
		}
		decoded_value = (decoded_value << 5) | index;
	}
	return decoded_value;
}

#endif
