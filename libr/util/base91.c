#include <string.h>

#include <r_util.h>

static const char b91[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
							'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
							'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
							'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
							'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
							'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
							'8', '9', '!', '#', '$', '%', '&', '(', ')', '*',
							'+', ',', '.', '/', ':', ';', '<', '=', '>', '?',
							'@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"'};

int get_char_index(const char c) {
	int i;
	for (i = 0; i < 91; i++ ) {
		if (b91[i] == c)
			return i;
	}
	return -1;
}

R_API int r_base91_decode(ut8* bout, const char *bin, int len) {
	int in, out;
	int v = -1;
	int b = 0;
	int n = 0;
	int c;
	if (len < 0)
		len = strlen (bin);
	for (in = out = 0; in < len; in++) {
		c = get_char_index(bin[in]);
		if (c == -1)
			continue;
		if (v < 0) {
			v = c;
		} else {
			v += c * 91;
			b |= (v << n);
			if ((v&8191) > 88) {
				n += 13;
			} else {
				n += 14;
			}
			while (true) {
				bout[out++] = b & 255;
				b >>= 8;
				n -= 8;
				if (n <= 7)
					break;
			}
			v = -1;
		}
	}
	if (v+1) {
		bout[out++] = (b | v << n) & 255;
	}
	return out;
}

R_API int r_base91_encode(char *bout, const ut8 *bin, int len) {
	int in, out;
	int v = 0;
	int b = 0;
	int n = 0;
	if (len < 0)
		len = strlen ((const char *)bin);
	for (in = out = 0; in < len; in++) {
		b |= (bin[in] << n);
		n += 8;
		if (n > 13) {
			v = b & 8191;
			if (v > 88) {
				b >>= 13;
				n -= 13;
			} else {
				v = b & 16383;
				b >>= 14;
				n -= 14;
			}
			bout[out++] = b91[v % 91];
			bout[out++] = b91[v / 91];
		}
	}
	if (n) {
		bout[out++] = b91[b % 91];
		if (n > 7 || b > 90) {
			bout[out++] = b91[b / 91];
		}
	}
	return out;
}
