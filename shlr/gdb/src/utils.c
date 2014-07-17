/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "r_types.h"
#include "utils.h"

// XXX: most of those functions are already implemented in r_util. reuse!

/**
 * Function creates the checksum
 * for the given command
 * - command : is used to calculate the checksum needs to be null terminated
 * @returns : calculated checksum
 */
uint8_t cmd_checksum(const char* command) {
	uint8_t sum = 0;
	while (*command != '\0') {
		sum += *command++;
	}
	return sum;
}

/**
 * Converts str to uint64_t
 */
uint64_t unpack_uint64(char *buff, int len) {
	int nibble;
	uint64_t retval = 0;
	while (len) {
		nibble = hex2int(*buff++);
		retval |= nibble;
		len--;
		if (len) retval = retval << 4;
	}
	return retval;
}

/**
 * Changed byte order and
 * converts the value into uint64_t
 */
uint64_t unpack_uint64_co(char* buff, int len) {
	uint64_t result = 0;
	int i;
	for (i = len - 2; i >= 0; i-=2) {
		result |= unpack_uint64 (&buff[i], 2);
		if (i) result <<= 8;
	}
	return result;
}

/**
 * Converts a given hex character into its int value
 * @returns value of hex or -1 on error
 */
int hex2int(int ch) {
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
	if (ch >= '0' && ch <= '9') return ch - '0';
	return -1;
}

/**
 * Converts a given nibble (4bit) into its hex representation
 * @returns hex char or -1 on error
 */
int int2hex(int i) {
	if (i >= 0 && i <= 9) return i + 48;
	if (i >= 10 && i <= 15) return i + 87;
	return -1;
}

char hex2char(char* hex) {
	uint8_t result = hex2int ((int)hex[0]);
	result <<= 4;
	result |= hex2int (hex[1]);
	return (char) result;
}

int unpack_hex(char* src, ut64 len, char* dst) {
	int i = 0;
	while (i < (len / 2)) {
		int val = hex2int (src[(i*2)]);
		val <<= 4;
		val |= hex2int (src[(i*2)+1]);
		dst[i++] = val;
	}
	dst[i] = '\0';
	return len;
}

int pack_hex(char* src, ut64 len, char* dst) {
	int i = 0;
	int x = 0;
	while (i < (len*2)) {
		int val = (src[x] & 0xf0) >> 4;
		dst[i++] = int2hex (val);
		dst[i++] = int2hex (src[x++] & 0x0f);
	}
	dst[i] = '\0';
	return (len/2);
}

void hexdump(void* ptr, ut64 len, ut64 offset) {
	unsigned char* data = (unsigned char*)ptr;
	int x = 0;
	char hex[49], *p;
	char txt[17], *c;
	ut64 curr_offset;
	while (x < len) {
		p = hex;
		c = txt;
		curr_offset = x+offset;

		do {
			p += sprintf (p, "%02x ", data[x]);
			*c++ = (data[x] >= 32 && data[x] <= 127) ? data[x] : '.';
		} while (++x % 16 && x < len);

		*c = '\0';
		eprintf ("0x%016"PFMT64x": %-48s- %s\n", (curr_offset), hex, txt);
	}
}
