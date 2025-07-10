/* xxHash - Fast Hash algorithm 2012 Yann Collet */

#if 0
Copyright (C) 2012, Yann Collet.

Cleanup and refactor for r2 in 2017: pancake@nopcode.org

BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

You can contact the author at :
- xxHash source repository: https://code.google.com/p/xxhash/
#endif

#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include "xxhash.h"

#define XXH_rotl32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

#define PRIME32_1   2654435761U
#define PRIME32_2   2246822519U
#define PRIME32_3   3266489917U
#define PRIME32_4    668265263U
#define PRIME32_5    374761393U

ut32 XXH32(const void *input, size_t len, ut32 seed) {
	const ut8 *p = (const ut8 *) input;
	const ut8 *const bEnd = p + len;
	ut32 h32;

	if (len >= 16) {
		const ut8 *const limit = bEnd - 16;
		ut32 v1 = seed + PRIME32_1 + PRIME32_2;
		ut32 v2 = seed + PRIME32_2;
		ut32 v3 = seed + 0;
		ut32 v4 = seed - PRIME32_1;

		do {
			v1 += r_read_le32 (p) * PRIME32_2;
			v1 = XXH_rotl32 (v1, 13);
			v1 *= PRIME32_1;
			p += 4;
			v2 += r_read_le32 (p) * PRIME32_2;
			v2 = XXH_rotl32 (v2, 13);
			v2 *= PRIME32_1;
			p += 4;
			v3 += r_read_le32 (p) * PRIME32_2;
			v3 = XXH_rotl32 (v3, 13);
			v3 *= PRIME32_1;
			p += 4;
			v4 += r_read_le32 (p) * PRIME32_2;
			v4 = XXH_rotl32 (v4, 13);
			v4 *= PRIME32_1;
			p += 4;
		} while (p <= limit);

		h32 = XXH_rotl32 (v1, 1) + XXH_rotl32 (v2, 7) +
		XXH_rotl32 (v3, 12) + XXH_rotl32 (v4, 18);
	} else {
		h32 = seed + PRIME32_5;
	}

	h32 += (ut32) len;

	while (p <= bEnd - 4) {
		h32 += r_read_le32 (p) * PRIME32_3;
		h32 = XXH_rotl32 (h32, 17) * PRIME32_4;
		p += 4;
	}

	while (p < bEnd) {
		h32 += (*p) * PRIME32_5;
		h32 = XXH_rotl32 (h32, 11) * PRIME32_1;
		p++;
	}

	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;

	return h32;
}

struct XXH_state32_t {
	ut32 seed;
	ut32 v1;
	ut32 v2;
	ut32 v3;
	ut32 v4;
	ut64 total_len;
	char memory[16];
	int memsize;
};

void *XXH32_init (ut32 seed) {
	struct XXH_state32_t *state =
		(struct XXH_state32_t *) malloc (sizeof (struct XXH_state32_t));
	if (!state) {
		return NULL;
	}
	state->seed = seed;
	state->v1 = seed + PRIME32_1 + PRIME32_2;
	state->v2 = seed + PRIME32_2;
	state->v3 = seed + 0;
	state->v4 = seed - PRIME32_1;
	state->total_len = 0;
	state->memsize = 0;
	return (void *) state;
}

int XXH32_feed (void *state_in, const void *input, int len) {
	struct XXH_state32_t *state = state_in;
	const ut8 *p = (const ut8 *) input;
	const ut8 *const bEnd = p + len;

	state->total_len += len;
	// fill in tmp buffer
	if (state->memsize + len < 16) {
		memcpy (state->memory + state->memsize, input, len);
		state->memsize += len;
		return 0;
	}

	// some data left from previous feed
	if (state->memsize) {
		memcpy (state->memory + state->memsize, input, 16 - state->memsize);
		{
			const ut32 *p32 = (const ut32 *) state->memory;
			state->v1 += r_read_le32 (p32) * PRIME32_2;
			state->v1 = XXH_rotl32 (state->v1, 13);
			state->v1 *= PRIME32_1;
			p32++;
			state->v2 += r_read_le32 (p32) * PRIME32_2;
			state->v2 = XXH_rotl32 (state->v2, 13);
			state->v2 *= PRIME32_1;
			p32++;
			state->v3 += r_read_le32 (p32) * PRIME32_2;
			state->v3 = XXH_rotl32 (state->v3, 13);
			state->v3 *= PRIME32_1;
			p32++;
			state->v4 += r_read_le32 (p32) * PRIME32_2;
			state->v4 = XXH_rotl32 (state->v4, 13);
			state->v4 *= PRIME32_1;
			p32++;
		}
		p += 16 - state->memsize;
		state->memsize = 0;
	}

	{
		const ut8 *const limit = bEnd - 16;
		ut32 v1 = state->v1;
		ut32 v2 = state->v2;
		ut32 v3 = state->v3;
		ut32 v4 = state->v4;

		while (p <= limit) {
			v1 += r_read_le32 (p) * PRIME32_2;
			v1 = XXH_rotl32 (v1, 13);
			v1 *= PRIME32_1;
			p += 4;
			v2 += r_read_le32 (p) * PRIME32_2;
			v2 = XXH_rotl32 (v2, 13);
			v2 *= PRIME32_1;
			p += 4;
			v3 += r_read_le32 (p) * PRIME32_2;
			v3 = XXH_rotl32 (v3, 13);
			v3 *= PRIME32_1;
			p += 4;
			v4 += r_read_le32 (p) * PRIME32_2;
			v4 = XXH_rotl32 (v4, 13);
			v4 *= PRIME32_1;
			p += 4;
		}
		state->v1 = v1;
		state->v2 = v2;
		state->v3 = v3;
		state->v4 = v4;
	}

	if (p < bEnd) {
		state->memsize = R_MIN (bEnd - p, sizeof (state->memory));
		memcpy (state->memory, p, state->memsize);
	}
	return 0;
}

ut32 XXH32_getIntermediateResult (void *state_in) {
	struct XXH_state32_t *state = state_in;
	ut8 *p = (ut8 *) state->memory;
	ut8 *bEnd = (ut8 *) state->memory + state->memsize;
	ut32 h32;

	if (state->total_len >= 16) {
		h32 = XXH_rotl32 (state->v1, 1) + XXH_rotl32 (state->v2, 7) +
		XXH_rotl32 (state->v3, 12) + XXH_rotl32 (state->v4, 18);
	} else {
		h32 = state->seed + PRIME32_5;
	}

	h32 += (ut32) state->total_len;

	while (p <= bEnd - 4) {
		h32 += r_read_le32 (p) * PRIME32_3;
		h32 = XXH_rotl32 (h32, 17) * PRIME32_4;
		p += 4;
	}
	while (p < bEnd) {
		h32 += (*p) * PRIME32_5;
		h32 = XXH_rotl32 (h32, 11) * PRIME32_1;
		p++;
	}
	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;
	return h32;
}

ut32 XXH32_result (void *state_in) {
	ut32 h32 = XXH32_getIntermediateResult (state_in);
	free (state_in);
	return h32;
}
