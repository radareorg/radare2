/* radare2's lz4 - Copyright 2024 - MIT - pancake */
/* Based on public domain implementation from lz4
 * Authors: Laurent Chardon, Ilya Muravyov */

#include <r_util.h>

#define BLOCK_SIZE (1024 * 8) /* 8K */
#define PADDING_LITERALS 5
#define WINDOW_BITS 10
#define WINDOW_SIZE (1 << WINDOW_BITS)
#define WINDOW_MASK (WINDOW_SIZE - 1)

#define MIN_MATCH 4

#define EXCESS (16 + (BLOCK_SIZE / 255))

#define LOAD_16(p) *(ut16*)&g_buf[(p)]
#define LOAD_32(p) *(ut32*)&g_buf[(p)]
#define LOAD_32_FROM(p, x)     *(ut32 *)&x[(p)]
#define COPY_32(d, s) *(ut32*)&g_buf[(d)] = LOAD_32((s))

// Using memcpy for these two because they make ASAN happy
// Avoids the 'misaligned address' error
#define COPY_32_TO(d, s, x, y) memcpy (&x[d], &y[s], 4)
#define LOAD_16_TO(p, x)       memcpy (&x, &g_buf[p], 2)

#define HASH_BITS 12
#define HASH_SIZE (1 << HASH_BITS)
#define HASH_32(p) ((LOAD_32(p)*0x9E3779B9)>>(32-HASH_BITS))

static int lz4_compress(ut8 *g_buf, const int uc_length, int max_chain) {
	int i, dist, limit, run, j;
	int len, chain_len, best_len, nib;
	int op = BLOCK_SIZE;
	int pp = 0;
	int p = 0;
	int head[HASH_SIZE];
	int tail[WINDOW_SIZE];
	for (i = 0; i < HASH_SIZE; i++) {
		head[i] = -1;
	}
	// Initialize tail array to prevent using uninitialized values
	for (i = 0; i < WINDOW_SIZE; i++) {
		tail[i] = -1;
	}

	while (p < uc_length) {
		best_len = 0;
		dist = 0;

		const int max_match = (uc_length-PADDING_LITERALS)-p;
		if (max_match >= R_MAX (12 - PADDING_LITERALS, MIN_MATCH)) {
			limit = R_MAX (p - WINDOW_SIZE, -1);
			chain_len = max_chain;

			int s = head[HASH_32(p)];
			while (s > limit) {
				if (g_buf[s + best_len] == g_buf[p + best_len] && LOAD_32 (s) == LOAD_32 (p)) {
					len = MIN_MATCH;
					while (len < max_match && g_buf[s+len] == g_buf[p+len]) {
						len++;
					}
					if (len > best_len) {
						best_len = len;
						dist = p - s;
						if (len == max_match) {
							break;
						}
					}
				}
				if (--chain_len == 0) {
					break;
				}
				s = tail[s & WINDOW_MASK];
			}
		}

		if (best_len >= MIN_MATCH) {
			len = best_len - MIN_MATCH;
			nib = R_MIN (len, 15);

			if (pp != p) {
				run = p-pp;
				if (run >= 15) {
					g_buf[op++] = (15 << 4) + nib;
					j = run - 15;
					for (; j >= 255; j -= 255) {
						g_buf[op++] = 255;
					}
					g_buf[op++] = j;
				} else {
					g_buf[op++] = (run << 4) + nib;
				}
				COPY_32 (op, pp);
				COPY_32 (op + 4, pp + 4);
				for (i = 8; i < run; i += 8) {
					COPY_32 (op + i, pp + i);
					COPY_32 (op + 4 + i, pp + 4 + i);
				}
				op += run;
			} else {
				g_buf[op++] = nib;
			}
			r_write_le16 (g_buf + op, dist);
			op += 2;

			if (len >= 15) {
				len -= 15;
				for (; len >= 255; len-=255) {
					g_buf[op++] = 255;
				}
				g_buf[op++] = len;
			}

			pp = p + best_len;

			while (p < pp) {
				const ut32 h = HASH_32(p);
				tail[p & WINDOW_MASK] = head[h];
				head[h] = p++;
			}
		} else {
			const ut32 h = HASH_32 (p);
			tail[p&WINDOW_MASK] = head[h];
			head[h] = p++;
		}
	}

	if (pp != p) {
		run = p-pp;
		if (run >= 15) {
			g_buf[op++] = 15 << 4;
			j = run-15;
			for (; j >= 255; j -= 255) {
				g_buf[op++] = 255;
			}
			g_buf[op++] = j;
		} else {
			g_buf[op++] = run << 4;
		}

		COPY_32(op, pp);
		COPY_32(op + 4, pp + 4);
		for (i = 8; i < run; i += 8) {
			COPY_32 (op + i, pp + i);
			COPY_32 (op + i + 4, pp + i + 4);
		}
		op += run;
	}
	return op - BLOCK_SIZE;
}

R_API int r_lz4_decompress_block(ut8 *g_buf, const int comp_len, int *pp, ut8 *obuf, int osz) {
	int i, s, len, run, p = 0;
	int ip = obuf? 0: BLOCK_SIZE;
	int maxLen = obuf? osz: BLOCK_SIZE;
	int ip_end = ip + comp_len;
	ut8 *dst = obuf? obuf: g_buf;
	ut16 tmp = 0;

	for (;;) {
		const int token = g_buf[ip++];
		if (token >= 16) {
			run = token >> 4;
			if (run == 15) {
				for (;;) {
					const int c = g_buf[ip++];
					run += c;
					if (c != 255) {
						break;
					}
				}
			}
			if ((p + run) > maxLen) {
				return -1;
			}

			// Avoid heap overflow
			memcpy (&dst[p], &g_buf[ip], run);

			p += run;
			ip += run;
			if (ip >= ip_end) {
				break;
			}
		}

		LOAD_16_TO (ip, tmp);
		s = p - tmp;
		ip += 2;
		if (s < 0) {
			return -1;
		}
		len = (token & 15) + MIN_MATCH;
		if (len == (15 + MIN_MATCH)) {
			for (;;) {
				const int c = g_buf[ip++];
				len += c;
				if (c != 255) {
					break;
				}
			}
		}
		if ((p + len) > maxLen) {
			return -1;
		}
		if ((p - s) >= 4) {
			COPY_32_TO (p, s, dst, dst);
			COPY_32_TO (p + 4, s + 4, dst, dst);
			for (i = 8; i < len; i += 8) {
				COPY_32_TO (p + i, s + i, dst, dst);
				COPY_32_TO (p + 4 + i, s + 4 + i, dst, dst);
			}
			p += len;
		} else {
			while (len-- != 0) {
				dst[p++] = dst[s++];
			}
		}
	}
	*pp = p;
	return 0;
}

R_API ut8 *r_lz4_decompress(const ut8* input, size_t input_size, size_t *output_size) {
	R_RETURN_VAL_IF_FAIL (input && output_size, NULL);
	RBuffer *b = r_buf_new ();
	ut8 g_buf[(BLOCK_SIZE + BLOCK_SIZE + EXCESS) * sizeof (ut8)];
	bool is_legacy = true;
	bool has_block_checksum = false, has_content_size = false, has_dictionary_id = false, has_content_checksum = false;
	const ut8 *input_last = input + input_size;

	// Process the lz4 header
	if (!memcmp (input, "\x02\x21\x4c\x18", 4)) {
		input += 4;
	} else if (!memcmp (input, "\x04\x22\x4d\x18", 4)) {
		is_legacy = false;
		input += 4;
		ut8 flag = r_read_le8 (input);
		input += 2; // skip BD byte
		has_block_checksum = flag & 16;
		has_content_size = flag & 8;
		has_content_checksum = flag & 4;
		has_dictionary_id = flag & 1;
		if (has_content_size) {
			input += 8;
		}
		if (has_dictionary_id) {
			input += 4;
		}
		input += 1; // skip header checksum
	}

	const ut8 bytes_at_end_to_skip = has_content_checksum? 8: 4;
	while (input + bytes_at_end_to_skip < input_last) {
		ut32 comp_len = r_read_le32 (input);
		bool is_compressed = is_legacy || (comp_len & 0x80000000) == 0;
		if (!is_legacy) {
			comp_len &= 0x7FFFFFFF;
		}
		input += 4;
		int p;
		memcpy (g_buf + BLOCK_SIZE, input, comp_len);
		if (is_compressed) {
			int error = r_lz4_decompress_block (g_buf, comp_len, &p, NULL, 0);
			if (error != 0) {
				r_buf_free (b);
				return NULL;
			}
		} else {
			p = comp_len;
		}
		r_buf_write (b, g_buf, p);
		input += comp_len;

		if (has_block_checksum) {
			input += 4;
		}
	}

	ut64 osz;
	ut8 *res = r_buf_drain (b, &osz);
	if (output_size) {
		*output_size = osz;
	}
	return res;
}

R_API int r_lz4_compress(ut8 *obuf, ut8 *buf, size_t buf_size, const int max_chain) {
	R_RETURN_VAL_IF_FAIL (obuf && buf, 0);
	int i;
	ut8 *obuf0 = obuf;
	ut8 g_buf[(BLOCK_SIZE + BLOCK_SIZE + EXCESS) * sizeof (ut8)];
	for (i = 0; i < buf_size; i += BLOCK_SIZE) {
		int n = R_MIN (BLOCK_SIZE, buf_size - i);
		memcpy (g_buf, buf + i, n);
		const int comp_len = lz4_compress (g_buf, n, max_chain);
		r_write_le32 (obuf, comp_len);
		obuf += sizeof (comp_len);
		memcpy (obuf, g_buf + BLOCK_SIZE, comp_len);
		obuf += comp_len;
	}
	return obuf - obuf0;
}

#if 0
int main() {
#if 0
	// compress test
	int level = 9;
	int clevel = (level<9)?1<<level:WINDOW_SIZE;
	FILE *f = fopen ("/tmp/a", "rb");
	ut8 input[32000];
	size_t input_size = fread (input, 1, sizeof (input), f);
	fclose (f);
	ut8 out[32000];
	int out_size = r_lz4_compress (out, input, input_size, clevel);
	write (1, "\x02\x21\x4c\x18", 4);
	write (1, out, out_size);
#else
	// decompress test
	FILE *f = fopen ("/tmp/a.lz4", "rb");
	ut8 input[32000];
	size_t input_size = fread (input, 1, sizeof (input), f);
	size_t output_size;
	ut8 *out = r_lz4_decompress(input, input_size, &output_size);
	write (1, out, output_size);
#endif
}
#endif
