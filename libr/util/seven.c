/* radare - LGPL - Copyright 2012-2025 - pancake */

#include <r_util.h>
// TODO: This api must be used from RCrypto. renamed to RCodec as a plugin

R_API char *r_print_pack7bit(const char *src) {
	R_RETURN_VAL_IF_FAIL (src, NULL);
	int i, j = 0, shift = 0;
	ut8 ch1, ch2;
	char tmp[4];

	int len = strlen (src);
	char *dest = calloc (1, len);
	if (!dest) {
		return NULL;
	}

	for (i = 0; i < len; i++) {
		ch1 = src[i] & 0x7F;
		ch1 = ch1 >> shift;
		ch2 = src[(i + 1)] & 0x7F;
		ch2 = ch2 << (7 - shift);
		ch1 = ch1 | ch2;

		snprintf (tmp, sizeof (tmp), "%x", (ch1 >> 4));
		dest[j++] = tmp[0];
		snprintf (tmp, sizeof (tmp), "%x", (ch1 & 0x0F));
		dest[j++] = tmp[0];
		dest[j++] = '\0';
		shift++;
		if (shift == 7) {
			shift = 0;
			i++;
		}
	}
	return dest;
}

R_API char *r_print_unpack7bit(const char *src) {
	R_RETURN_VAL_IF_FAIL (src, NULL);
	int i, j, shift = 0, len = strlen (src);
	ut8 ch1, ch2 = '\0';
	char buf[8];

	char *dest = calloc (1, len);
	if (!dest) {
		return NULL;
	}
	for (i = 0; i < len; i += 2) {
		snprintf (buf, sizeof (buf), "%c%c", src[i], src[i + 1]);
		ch1 = strtol (buf, NULL, 16);
		j = strlen (dest);
		dest[j++] = ((ch1 & (0x7F >> shift)) << shift) | ch2;
		dest[j++] = '\0';
		ch2 = ch1 >> (7 - shift);
		shift++;
	}
	return dest;
}
