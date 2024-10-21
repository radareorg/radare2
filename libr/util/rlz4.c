/* radare2's lz4 - Copyright 2024 - MIT - pancake */
/* Based on public domain implementation from lz4
 * Authors: Laurent Chardon, Ilya Muravyov */

#include <r_util.h>

#if R2_USE_NEW_ABI
// R2_600 - replace shlr/smallz4 with this code which also supports compressing

#define BLOCK_SIZE (1024*8) /* 8K */
#define PADDING_LITERALS 5
#define WINDOW_BITS 10
#define WINDOW_SIZE (1<<WINDOW_BITS)
#define WINDOW_MASK (WINDOW_SIZE-1)

#define MIN_MATCH 4

#define EXCESS (16 + (BLOCK_SIZE / 255))

#define LOAD_16(p) *(ut16*)&g_buf[(p)]
#define LOAD_32(p) *(ut32*)&g_buf[(p)]
#define STORE_16(p, x) *(ut16*)&g_buf[(p)] = (x)
#define COPY_32(d, s) *(ut32*)&g_buf[(d)] = LOAD_32((s))

#define HASH_BITS 12
#define HASH_SIZE (1 << HASH_BITS)
#define NIL (-1)

#define HASH_32(p) ((LOAD_32(p)*0x9E3779B9)>>(32-HASH_BITS))

/* Change endianness */
#define SWAP16(i) (((i) >> 8) | ((i) << 8))
#define SWAP32(i) ( (((i) >> 24) & 0x000000FF) | (((i) >> 8) & 0x0000FF00) | \
	(((i) << 8) & 0x00FF0000) | (((i) << 24) & 0xFF000000) )

static int lz4_compress(ut8 *g_buf, const int uc_length, int max_chain) {
	int i, dist, limit, run, j;
	int len, chain_len, best_len, nib;
	int op = BLOCK_SIZE;
	int pp = 0;
	int p = 0;
	int head[HASH_SIZE];
	int tail[WINDOW_SIZE];
	for (i = 0; i < HASH_SIZE; i++) {
		head[i]=NIL;
	}

	while (p < uc_length) {
		best_len = 0;
		dist = 0;

		const int max_match = (uc_length-PADDING_LITERALS)-p;
		if (max_match >= R_MAX (12-PADDING_LITERALS, MIN_MATCH)) {
			limit = R_MAX (p-WINDOW_SIZE, NIL);
			chain_len = max_chain;

			int s = head[HASH_32(p)];
			while (s > limit) {
				if (g_buf[s+best_len] == g_buf[p+best_len] && LOAD_32(s)==LOAD_32(p)) {
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
				s = tail[s&WINDOW_MASK];
			}
		}

		if (best_len >= MIN_MATCH) {
			len = best_len-MIN_MATCH;
			nib = R_MIN (len, 15);

			if (pp != p) {
				run = p-pp;
				if (run >= 15) {
					g_buf[op++] = (15<<4)+nib;
					j = run-15;
					for (; j >= 255; j-=255) {
						g_buf[op++] = 255;
					}
					g_buf[op++] = j;
				} else {
					g_buf[op++] = (run<<4)+nib;
				}
				COPY_32 (op, pp);
				COPY_32 (op+4, pp+4);
				for (i = 8; i < run; i+=8) {
					COPY_32 (op+i, pp+i);
					COPY_32 (op+4+i, pp+4+i);
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
			for (; j >= 255; j-=255) {
				g_buf[op++] = 255;
			}
			g_buf[op++] = j;
		} else {
			g_buf[op++] = run<<4;
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

static int lz4_decompress(ut8 *g_buf, const int comp_len, int *pp) {
	int i, s, len, error, run, p = 0;
	int ip = BLOCK_SIZE;
	int ip_end = ip + comp_len;

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
			if ((p+run)>BLOCK_SIZE) {
				return -1;
			}

			COPY_32 (p, ip);
			COPY_32 (p+4, ip+4);
			for (i = 8; i < run; i += 8) {
				COPY_32 (p+i, ip+i);
				COPY_32 (p+4+i, ip+4+i);
			}
			p += run;
			ip += run;
			if (ip >= ip_end) {
				break;
			}
		}

		s = p - LOAD_16 (ip);
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
		if ((p+len) > BLOCK_SIZE) {
			return -1;
		}
		if ((p-s) >= 4) {
			/* wild_copy(p, s, len); */
			COPY_32 (p, s);
			COPY_32 (p + 4, s + 4);
			for (i = 8; i < len; i += 8) {
				COPY_32 (p + i, s + i);
				COPY_32 (p + 4 + i, s + 4 + i);
			}
			p += len;
		} else {
			while (len-- != 0) {
				g_buf[p++] = g_buf[s++];
			}
		}
	}
	*pp = p;
	return 0;
}

R_API ut8 *r_lz4_decompress(const ut8* input, size_t input_size, size_t *output_size) {
	RBuffer *b = r_buf_new ();
	ut8 g_buf[(BLOCK_SIZE + BLOCK_SIZE + EXCESS) * sizeof (ut8)];
	const ut8 *input_last = input + input_size;
	while (input + 4 < input_last) {
		if (!memcmp (input, "\x02\x21\x4c\x18", 4)) {
			input += 4;
			continue;
		}
		ut32 comp_len = r_read_le32 (input);
		input += 4;
		int p;
		memcpy (g_buf + BLOCK_SIZE, input, comp_len);
		int error = lz4_decompress (g_buf, comp_len, &p);
		if (error != 0) {
			fprintf (stderr, "Invalid data\n");
			r_buf_free (b);
			return NULL;
		}
		r_buf_write (b, g_buf, p);
		input += comp_len;
	}
	*output_size = r_buf_size (b);
	return r_buf_tostring (b);
}

R_API int r_lz4_compress(ut8 *obuf, ut8 *buf, size_t buf_size, const int max_chain) {
	int i, n;
	ut8 *obuf0 = obuf;

	int ipos = 0;
	int opos = 0;
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

#endif
