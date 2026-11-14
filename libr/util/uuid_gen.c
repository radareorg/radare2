#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <r_util/r_uuid.h>
#include <r_util/r_time.h>
#include "uuid_hash.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#endif

/* ------------------------------------------------------------------ */
/* Deterministic stand-ins (always compiled, handy in unit tests)      */
/* ------------------------------------------------------------------ */

/* splitmix64: tiny, fast, good enough for fake data. NOT for real UUIDs. */
R_API bool r_uuid_fake_rand(ut8 *buf, size_t len, void *user) {
	ut64 *state = (ut64 *)user;
	size_t i = 0;
	if (!state || (len && !buf)) {
		return false;
	}
	while (i < len) {
		ut64 z = (*state += 0x9E3779B97F4A7C15ULL);
		int k;
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
		z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
		z ^= z >> 31;
		for (k = 0; k < 8 && i < len; k++, i++) {
			buf[i] = (ut8)(z >> (8 * k));
		}
	}
	return true;
}

R_API ut64 r_uuid_fake_now(void *user) {
	ut64 *t = (ut64 *)user;
	return t ? (*t)++ : 0;
}

/* ------------------------------------------------------------------ */
/* Default sources: OS CSPRNG and system clock, or fakes if R_UUID_FAKE */
/* ------------------------------------------------------------------ */

#ifdef R_UUID_FAKE

/* Build with -DR_UUID_FAKE for reproducible output while debugging.
 * The state is global and NOT thread-safe, which is fine for a debug stub. */
static ut64 g_fake_state = 0x2545F4914F6CDD1DULL;
static ut64 g_fake_ms = 1645557742000ULL;

static bool default_rand(ut8 *buf, size_t len) {
	return r_uuid_fake_rand (buf, len, &g_fake_state);
}

static bool default_now_ms(ut64 *ms) {
	*ms = g_fake_ms++;
	return true;
}

#elif defined(_WIN32)

static bool default_rand(ut8 *buf, size_t len) {
	return BCRYPT_SUCCESS (BCryptGenRandom (NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

static bool default_now_ms(ut64 *ms) {
	FILETIME ft;
	ULARGE_INTEGER t;
	GetSystemTimeAsFileTime (&ft);
	t.LowPart = ft.dwLowDateTime;
	t.HighPart = ft.dwHighDateTime;
	/* FILETIME counts 100ns since 1601-01-01 */
	*ms = (ut64)((t.QuadPart - 116444736000000000ULL) / 10000ULL);
	return true;
}

#else

static bool default_rand(ut8 *buf, size_t len) {
	int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
	size_t got = 0;
	if (fd < 0) {
		return false;
	}
	while (got < len) {
		ssize_t n = read (fd, buf + got, len - got);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			close (fd);
			return false;
		}
		if (n == 0) {
			close (fd);
			return false;
		}
		got += (size_t)n;
	}
	close (fd);
	return true;
}

static bool default_now_ms(ut64 *ms) {
	*ms = r_time_now () / R_USEC_PER_MSEC;
	return true;
}

#endif

/* ------------------------------------------------------------------ */
/* Entropy mixing                                                      */
/* ------------------------------------------------------------------ */

#define MIX_MAX 16

static bool get_now_ms(const RUuidOpts *o, ut64 *ms) {
	if (o->now_fn) {
		*ms = o->now_fn (o->now_user);
		return true;
	}
	return default_now_ms (ms);
}

static bool rand_raw(const RUuidOpts *o, ut8 *buf, size_t len) {
	if (o->rand_fn) {
		return o->rand_fn (buf, len, o->rand_user);
	}
	return default_rand (buf, len);
}

/* Fills out[0..len) from the base random source. When extra entropy sources
 * are given, the result is SHA-1(tag || base || (len || data)*), truncated.
 * The base randomness is always part of the hash input, so extra sources can
 * only add to the unpredictability, never replace it. Every extra is length
 * prefixed, so ("ab","c") and ("a","bc") give different results. */
static bool rand_mixed(const RUuidOpts *o, ut8 *out, size_t len) {
	ut8 base[MIX_MAX];
	size_t i;
	int k;

	if (len == 0 || len > MIX_MAX) {
		return false;
	}
	if (!rand_raw (o, base, len)) {
		return false;
	}
	if (!o->n_extra) {
		memcpy (out, base, len);
		return true;
	}
	if (!o->extra) {
		return false;
	}
	RUuidSha1 c;
	ut8 digest[20];
	ut8 lb[8];
	r_uuid_sha1_init (&c);
	r_uuid_sha1_update (&c, (const ut8 *)"r_uuid-mix\0", 11);
	r_uuid_sha1_update (&c, base, len);
	for (i = 0; i < o->n_extra; i++) {
		const RUuidEntropy *e = &o->extra[i];
		if (e->len && !e->data) {
			return false;
		}
		for (k = 0; k < 8; k++) {
			lb[k] = (ut8)((ut64)e->len >> (56 - 8 * k));
		}
		r_uuid_sha1_update (&c, lb, 8);
		if (e->len) {
			r_uuid_sha1_update (&c, e->data, e->len);
		}
	}
	r_uuid_sha1_final (&c, digest);
	memcpy (out, digest, len);
	return true;
}

/* ------------------------------------------------------------------ */
/* Pure builders                                                       */
/* ------------------------------------------------------------------ */

static void put32(ut8 *p, ut32 v) {
	p[0] = (ut8)(v >> 24);
	p[1] = (ut8)(v >> 16);
	p[2] = (ut8)(v >> 8);
	p[3] = (ut8)v;
}

static void put16(ut8 *p, ut32 v) {
	p[0] = (ut8)(v >> 8);
	p[1] = (ut8)v;
}

R_API bool r_uuid_make_v1(RUuid *u, ut64 ts, ut16 clock_seq, const ut8 node[6]) {
	if (!u || !node || (ts >> 60)) {
		return false;
	}
	put32 (u->b, (ut32)(ts & 0xFFFFFFFFu));          /* time_low */
	put16 (u->b + 4, (ut32)((ts >> 32) & 0xFFFF));   /* time_mid */
	put16 (u->b + 6, (ut32)((ts >> 48) & 0x0FFF));   /* time_hi, version added below */
	u->b[8] = (ut8)((clock_seq >> 8) & 0x3F);
	u->b[9] = (ut8)(clock_seq & 0xFF);
	memcpy (u->b + 10, node, 6);
	r_uuid_finalize (u, R_UUID_V1, R_UUID_VAR_RFC);
	return true;
}

R_API bool r_uuid_make_v2(RUuid *u, ut64 ts, ut8 clock_seq, ut8 domain, ut32 local_id, const ut8 node[6]) {
	if (!u || !node || (ts >> 60) || domain > 2 || clock_seq > 0x3F) {
		return false;
	}
	put32 (u->b, local_id);
	put16 (u->b + 4, (ut32)((ts >> 32) & 0xFFFF));
	put16 (u->b + 6, (ut32)((ts >> 48) & 0x0FFF));
	u->b[8] = clock_seq;
	u->b[9] = domain;
	memcpy (u->b + 10, node, 6);
	r_uuid_finalize (u, R_UUID_V2, R_UUID_VAR_RFC);
	return true;
}

R_API bool r_uuid_make_v6(RUuid *u, ut64 ts, ut16 clock_seq, const ut8 node[6]) {
	if (!u || !node || (ts >> 60)) {
		return false;
	}
	put32 (u->b, (ut32)(ts >> 28));                  /* time_high */
	put16 (u->b + 4, (ut32)((ts >> 12) & 0xFFFF));   /* time_mid */
	put16 (u->b + 6, (ut32)(ts & 0x0FFF));           /* time_low, version added below */
	u->b[8] = (ut8)((clock_seq >> 8) & 0x3F);
	u->b[9] = (ut8)(clock_seq & 0xFF);
	memcpy (u->b + 10, node, 6);
	r_uuid_finalize (u, R_UUID_V6, R_UUID_VAR_RFC);
	return true;
}

R_API bool r_uuid_make_v3(RUuid *u, const RUuid *ns, const ut8 *name, size_t len) {
	RUuidMd5 c;
	ut8 digest[16];
	if (!u || !ns || (len && !name)) {
		return false;
	}
	r_uuid_md5_init (&c);
	r_uuid_md5_update (&c, ns->b, 16);
	if (len) {
		r_uuid_md5_update (&c, name, len);
	}
	r_uuid_md5_final (&c, digest);
	memcpy (u->b, digest, 16);
	r_uuid_finalize (u, R_UUID_V3, R_UUID_VAR_RFC);
	return true;
}

R_API bool r_uuid_make_v5(RUuid *u, const RUuid *ns, const ut8 *name, size_t len) {
	RUuidSha1 c;
	ut8 digest[20];
	if (!u || !ns || (len && !name)) {
		return false;
	}
	r_uuid_sha1_init (&c);
	r_uuid_sha1_update (&c, ns->b, 16);
	if (len) {
		r_uuid_sha1_update (&c, name, len);
	}
	r_uuid_sha1_final (&c, digest);
	memcpy (u->b, digest, 16);
	r_uuid_finalize (u, R_UUID_V5, R_UUID_VAR_RFC);
	return true;
}

R_API bool r_uuid_make_v4(RUuid *u, const ut8 rnd[16]) {
	if (!u || !rnd) {
		return false;
	}
	memcpy (u->b, rnd, 16);
	r_uuid_finalize (u, R_UUID_V4, R_UUID_VAR_RFC);
	return true;
}

R_API bool r_uuid_make_v7(RUuid *u, ut64 unix_ms, const ut8 rnd[10]) {
	if (!u || !rnd || (unix_ms >> 48)) {
		return false;
	}
	put32 (u->b, (ut32)(unix_ms >> 16));
	put16 (u->b + 4, (ut32)(unix_ms & 0xFFFF));
	memcpy (u->b + 6, rnd, 10);
	r_uuid_finalize (u, R_UUID_V7, R_UUID_VAR_RFC);
	return true;
}

R_API bool r_uuid_make_v8(RUuid *u, const ut8 custom[16]) {
	if (!u || !custom) {
		return false;
	}
	memcpy (u->b, custom, 16);
	r_uuid_finalize (u, R_UUID_V8, R_UUID_VAR_RFC);
	return true;
}

/* ------------------------------------------------------------------ */
/* Generators: gather inputs from opts, then call a builder            */
/* ------------------------------------------------------------------ */

/* The Gregorian versions share a timestamp and random node. The random node
 * has its multicast bit set because no hardware address is used. */
static bool get_gregorian_data(const RUuidOpts *o, ut64 *ts, ut8 rnd[8], ut8 node[6]) {
	ut64 ms;
	ut64 max_ms = (((1ULL << 60) - 1) - R_UUID_GREGORIAN_OFFSET) / 10000ULL;
	if (!get_now_ms (o, &ms) || ms > max_ms || !rand_mixed (o, rnd, 8)) {
		return false;
	}
	memcpy (node, rnd + 2, 6);
	node[0] |= 0x01;
	*ts = ms * 10000ULL + R_UUID_GREGORIAN_OFFSET;
	return true;
}

/* v1/v6 use a 14-bit sequence with the shared Gregorian timestamp and node. */
static bool gen_gregorian(RUuid *u, const RUuidOpts *o, bool v6) {
	ut64 ts;
	ut8 rnd[8];
	ut8 node[6];
	ut16 cs;
	if (!get_gregorian_data (o, &ts, rnd, node)) {
		return false;
	}
	cs = (ut16)((((ut16)rnd[0] << 8) | rnd[1]) & 0x3FFF);
	return v6 ? r_uuid_make_v6 (u, ts, cs, node) : r_uuid_make_v1 (u, ts, cs, node);
}

static bool gen_v1(RUuid *u, const RUuidOpts *o) {
	return gen_gregorian (u, o, false);
}

static bool gen_v2(RUuid *u, const RUuidOpts *o) {
	ut64 ts;
	ut8 rnd[8];
	ut8 node[6];
	if (!get_gregorian_data (o, &ts, rnd, node)) {
		return false;
	}
	return r_uuid_make_v2 (u, ts, rnd[0] & 0x3F, o->v2_domain, o->v2_local_id, node);
}

static bool gen_v6(RUuid *u, const RUuidOpts *o) {
	return gen_gregorian (u, o, true);
}

static bool gen_v3(RUuid *u, const RUuidOpts *o) {
	return r_uuid_make_v3 (u, o->ns, o->name, o->name_len);
}

static bool gen_v5(RUuid *u, const RUuidOpts *o) {
	return r_uuid_make_v5 (u, o->ns, o->name, o->name_len);
}

static bool gen_v4(RUuid *u, const RUuidOpts *o) {
	ut8 r[16];
	return rand_mixed (o, r, sizeof (r)) && r_uuid_make_v4 (u, r);
}

static bool gen_v7(RUuid *u, const RUuidOpts *o) {
	ut64 ms;
	ut8 r[10];
	if (!get_now_ms (o, &ms)) {
		return false;
	}
	return rand_mixed (o, r, sizeof (r)) && r_uuid_make_v7 (u, ms, r);
}

static bool gen_v8(RUuid *u, const RUuidOpts *o) {
	ut8 c[16];
	if (o->custom_fn) {
		if (!o->custom_fn (c, o->custom_user)) {
			return false;
		}
		return r_uuid_make_v8 (u, c);
	}
	if (o->custom) {
		return r_uuid_make_v8 (u, o->custom);
	}
	return rand_mixed (o, c, sizeof (c)) && r_uuid_make_v8 (u, c);
}

/* ------------------------------------------------------------------ */
/* Dispatch table                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
	RUuidVersion version;
	const char *name;
	const char *desc;
	bool (*gen)(RUuid *out, const RUuidOpts *opts);
} RUuidGen;

static const RUuidGen gens[] = {
	{ R_UUID_V1, "v1", "Gregorian time + random node and clock sequence", gen_v1 },
	{ R_UUID_V2, "v2", "DCE security: Gregorian time + local ID", gen_v2 },
	{ R_UUID_V3, "v3", "name-based, MD5 (needs namespace and name)", gen_v3 },
	{ R_UUID_V4, "v4", "random", gen_v4 },
	{ R_UUID_V5, "v5", "name-based, SHA-1 (needs namespace and name)", gen_v5 },
	{ R_UUID_V6, "v6", "reordered Gregorian time, sortable v1", gen_v6 },
	{ R_UUID_V7, "v7", "Unix-ms time + random, sortable", gen_v7 },
	{ R_UUID_V8, "v8", "custom: your function, your bytes, or derived", gen_v8 }
};

static const RUuidGen *find_gen(int version) {
	size_t i;
	for (i = 0; i < sizeof (gens) / sizeof (gens[0]); i++) {
		if ((int)gens[i].version == version) {
			return &gens[i];
		}
	}
	return NULL;
}

R_API bool r_uuid_version_supported(RUuidVersion v) {
	return find_gen ((int)v) != NULL;
}

R_API const char *r_uuid_version_name(RUuidVersion v) {
	const RUuidGen *g = find_gen ((int)v);
	return g ? g->name : NULL;
}

R_API const char *r_uuid_version_desc(RUuidVersion v) {
	const RUuidGen *g = find_gen ((int)v);
	return g ? g->desc : NULL;
}

R_API int r_uuid_version_from_name(const char *s) {
	int n = 0;
	int digits = 0;
	if (!s) {
		return -1;
	}
	if (*s == 'v' || *s == 'V') {
		s++;
	}
	while (*s >= '0' && *s <= '9') {
		if (++digits > 2) {
			return -1;
		}
		n = n * 10 + (*s - '0');
		s++;
	}
	if (!digits || *s) {
		return -1;
	}
	return find_gen (n) ? n : -1;
}

/* ------------------------------------------------------------------ */
/* Public entry points                                                 */
/* ------------------------------------------------------------------ */

R_API void r_uuid_opts_init(RUuidOpts *o) {
	if (o) {
		memset (o, 0, sizeof (*o));
	}
}

R_API bool r_uuid_generate(RUuid *out, RUuidVersion v, const RUuidOpts *opts) {
	static const RUuidOpts defaults = { 0 };
	const RUuidGen *g;
	RUuid tmp;

	if (!out) {
		return false;
	}
	if (!opts) {
		opts = &defaults;
	}
	g = find_gen ((int)v);
	if (!g || !g->gen (&tmp, opts)) {
		return false;
	}
	*out = tmp;
	if (opts->audit_fn) {
		opts->audit_fn (out, v, opts->audit_user);
	}
	return true;
}

R_API size_t r_uuid_generate_n(RUuid *out, size_t n, RUuidVersion v, const RUuidOpts *opts) {
	size_t i;
	if (!out) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		if (!r_uuid_generate (out + i, v, opts)) {
			break;
		}
	}
	return i;
}
