/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_DEBUG_NATIVE_REG_VECTOR_H
#define R_DEBUG_NATIVE_REG_VECTOR_H

typedef struct {
	int arena;
	int state;
	int size;
	int count;
	int arena_stride;
	int state_stride;
} NativeRegSlice;

// Validate every slice before modifying either buffer; preserve unrepresented state.
static inline bool native_reg_transfer(ut8 *arena, int arena_size, ut8 *state, int state_size, const NativeRegSlice *slices, int count, bool write) {
	int i, j;
	for (i = 0; i < count; i++) {
		const NativeRegSlice *s = &slices[i];
		if (s->arena < 0 || s->state < 0 || s->size < 1 || s->count < 1
				|| s->arena_stride < 0 || s->state_stride < 0
				|| (st64)s->arena + (st64)(s->count - 1) * s->arena_stride + s->size > arena_size
				|| (st64)s->state + (st64)(s->count - 1) * s->state_stride + s->size > state_size) {
			return false;
		}
	}
	for (i = 0; i < count; i++) {
		const NativeRegSlice *s = &slices[i];
		for (j = 0; j < s->count; j++) {
			ut8 *a = arena + s->arena + j * s->arena_stride;
			ut8 *b = state + s->state + j * s->state_stride;
			memcpy (write? b: a, write? a: b, s->size);
		}
	}
	return true;
}

typedef struct {
	int legacy;
	int ymm;
	int opmask;
	int zmm;
	int hi16;
} NativeX86Layout;

#if __linux__ && __x86_64__
static inline void native_x86_cpuid(ut32 leaf, ut32 subleaf, ut32 *eax, ut32 *ebx, ut32 *ecx, ut32 *edx) {
	__asm__ volatile ("cpuid"
		: "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		: "a" (leaf), "c" (subleaf));
}
#endif

static inline bool native_x86_transfer(ut8 *arena, int arena_size, ut8 *state, int state_size, const NativeX86Layout *layout, int bits, int width, bool write) {
	if (width != 128 && width != 256 && width != 512) {
		return false;
	}
	const int stride = width / 8;
	const int low_count = bits == 64? 16: 8;
	const int count = bits == 64 && width == 512? 32: low_count;
	const NativeRegSlice slices[] = {
		{ 0, layout->legacy, 160, 1, 0, 0 },
		{ 160, layout->legacy + 160, 16, low_count, stride, 16 },
		{ 176, layout->ymm, 16, low_count, stride, 16 },
		{ 160 + count * stride, layout->opmask, 64, 1, 0, 0 },
		{ 192, layout->zmm, 32, low_count, stride, 32 },
		{ 160 + 16 * stride, layout->hi16, 64, 16, stride, 64 },
	};
	const int n = width == 128? 2: width == 256? 3: bits == 64? 6: 5;
	return native_reg_transfer (arena, arena_size, state, state_size, slices, n, write);
}

static inline char *native_x86_profile(char *base, int bits, int width) {
	if (!base) {
		return NULL;
	}
	RStrBuf *profile = r_strbuf_new (base);
	free (base);
	r_strbuf_append (profile, "fpu cwd .16 0 0\nfpu swd .16 2 0\nfpu ftw .8 4 0\nfpu fop .16 6 0\n"
		"fpu frip .64 8 0\nfpu frdp .64 16 0\nfpu mxcsr .32 24 0\nfpu mxcr_mask .32 28 0\n");
	int i;
	for (i = 0; i < 8; i++) {
		r_strbuf_appendf (profile, "fpu st%d .80 %d 0\nvec64@fpu mm%d .64 %d 8\n", i, 32 + i * 16, i, 32 + i * 16);
	}
	const int count = bits == 64? (width == 512? 32: 16): 8;
	for (i = 0; i < count; i++) {
		const int offset = 160 + i * (width / 8);
		r_strbuf_appendf (profile, "vec128@fpu xmm%d .128 %d 4\nfpu xmm%dl .64 %d 0\nfpu xmm%dh .64 %d 0\n",
			i, offset, i, offset, i, offset + 8);
		if (width >= 256) {
			r_strbuf_appendf (profile, "vec256@fpu ymm%d .256 %d 4\n", i, offset);
		}
		if (width == 512) {
			r_strbuf_appendf (profile, "vec512@fpu zmm%d .512 %d 4\n", i, offset);
		}
	}
	if (width == 512) {
		for (i = 0; i < 8; i++) {
			r_strbuf_appendf (profile, "fpu k%d .64 %d 0\n", i, 160 + count * 64 + i * 8);
		}
	}
	return r_strbuf_drain (profile);
}

static inline int native_vector_width(RReg *reg, const char *name) {
	RRegItem *item = r_reg_get (reg, name, R_REG_TYPE_ALL);
	const int width = item? item->size: 0;
	r_unref (item);
	return width;
}

static inline char *native_arm64_profile(char *base, int vl, bool sve) {
	if (!base) {
		return NULL;
	}
	RStrBuf *profile = r_strbuf_new (base);
	free (base);
	int i;
	for (i = 0; i < 32; i++) {
		const int off = i * vl;
		r_strbuf_appendf (profile,
			"fpu b%d .8 %d 0\nfpu h%d .16 %d 0\nfpu s%d .32 %d 0\nfpu d%d .64 %d 0\n"
			"vec128@fpu v%d .128 %d 4\nvec128@fpu q%d .128 %d 4\nfpu v%dl .64 %d 0\nfpu v%dh .64 %d 0\n",
			i, off + (R_SYS_ENDIAN && !sve? 7: 0), i, off + (R_SYS_ENDIAN && !sve? 6: 0), i, off + (R_SYS_ENDIAN && !sve? 4: 0), i, off,
			i, off, i, off, i, off, i, off + 8);
	}
	int end = 32 * vl;
	if (sve) {
		r_strbuf_appendf (profile, "fpu z[32] .%d 0 %d\nfpu p[16] .%d %d %d\nfpu ffr .%d %d 1\n",
			vl * 8, vl, vl, end, vl / 8, vl, end + 2 * vl);
		end += 17 * (vl / 8);
	}
	r_strbuf_appendf (profile, "fpu fpsr .32 %d 0\nfpu fpcr .32 %d 0\n", end, end + 4);
	return r_strbuf_drain (profile);
}

// FPSIMD stores whole host-endian 128-bit values; RReg stores low-first 64-bit chunks.
static inline bool native_arm64_fpsimd(ut8 *arena, int arena_size, ut8 *state, int state_size, int vl, bool sve, bool be, bool write) {
	if (vl < 16 || vl > 256 || (vl & 15)) {
		return false;
	}
	const int status = 32 * vl + (sve? 17 * (vl / 8): 0);
	if (arena_size < status + 8 || state_size < 520) {
		return false;
	}
	if (!write) {
		memset (arena, 0, status + 8);
	}
	int i, j;
	for (i = 0; i < 32; i++) {
		for (j = 0; j < 16; j++) {
			ut8 *a = arena + i * vl + r_reg_value_byte_offset (j, 16, be);
			ut8 *b = state + i * 16 + (be? 15 - j: j);
			*(write? b: a) = *(write? a: b);
		}
	}
	memcpy (write? state + 512: arena + status, write? arena + status: state + 512, 8);
	return true;
}

// Linux SVE payloads use little-endian byte order even on big-endian targets.
static inline bool native_arm64_sve(ut8 *arena, int arena_size, ut8 *state, int state_size, int vl, bool be, bool write) {
	if (vl < 16 || vl > 256 || (vl & 15)) {
		return false;
	}
	const int vectors = 32 * vl;
	const int predicates = 17 * (vl / 8);
	const int status = vectors + predicates;
	const int state_status = (16 + status + 15) & ~15;
	if (arena_size < status + 8 || state_size < state_status + 8) {
		return false;
	}
	int i;
	for (i = 0; i < status; i++) {
		const int stride = i < vectors? vl: vl / 8;
		const int offset = i < vectors? i: i - vectors;
		ut8 *a = arena + i - (offset % stride) + r_reg_value_byte_offset (offset % stride, stride, be);
		ut8 *b = state + 16 + i;
		*(write? b: a) = *(write? a: b);
	}
	memcpy (write? state + state_status: arena + status, write? arena + status: state + state_status, 8);
	return true;
}

#endif
