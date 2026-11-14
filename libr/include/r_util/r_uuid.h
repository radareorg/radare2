#ifndef R_UUID_H
#define R_UUID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <r_types.h>

/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (+ NUL) */
#define R_UUID_STR_LEN  36
#define R_UUID_STR_SIZE 37
/* largest text form: "urn:uuid:" + 36 + NUL */
#define R_UUID_STR_FMT_MAX  46
/* enough for the object produced by r_uuid_to_json() */
#define R_UUID_JSON_MAX 192

/* 100ns intervals between 1582-10-15 (UUID epoch) and 1970-01-01 */
#define R_UUID_GREGORIAN_OFFSET 0x01B21DD213814000ULL

typedef struct {
	ut8 b[16]; /* network (big-endian) byte order, as in RFC 9562 */
} RUuid;

typedef enum {
	R_UUID_V0 = 0,
	R_UUID_V1 = 1,
	R_UUID_V2 = 2,
	R_UUID_V3 = 3,
	R_UUID_V4 = 4,
	R_UUID_V5 = 5,
	R_UUID_V6 = 6,
	R_UUID_V7 = 7,
	R_UUID_V8 = 8,
	R_UUID_V_MAX = 9
} RUuidVersion;

typedef enum {
	R_UUID_VAR_NCS,    /* 0xxx */
	R_UUID_VAR_RFC,    /* 10xx (RFC 4122 / RFC 9562) */
	R_UUID_VAR_MS,     /* 110x (Microsoft GUID) */
	R_UUID_VAR_FUTURE, /* 111x */
	R_UUID_VAR_MAX
} RUuidVariant;

typedef enum {
	R_UUID_FMT_STD,     /* 017f22e2-79b0-7cc3-98c4-dc0c0c07398f */
	R_UUID_FMT_UPPER,   /* 017F22E2-79B0-7CC3-98C4-DC0C0C07398F */
	R_UUID_FMT_COMPACT, /* 017f22e279b07cc398c4dc0c0c07398f */
	R_UUID_FMT_BRACES,  /* {017f22e2-...} */
	R_UUID_FMT_URN,     /* urn:uuid:017f22e2-... */
	R_UUID_FMT_MAX
} RUuidFmt;

/* ------------------------------------------------------------------ */
/* Core: bits, text, comparison                                        */
/* ------------------------------------------------------------------ */

R_API void r_uuid_set_version(RUuid *u, RUuidVersion v);
R_API void r_uuid_set_variant(RUuid *u, RUuidVariant v);
/* Every generator ends with this, so the bits can't be forgotten. */
R_API void r_uuid_finalize(RUuid *u, RUuidVersion v, RUuidVariant var);

R_API RUuidVariant r_uuid_get_variant(const RUuid *u);
/* Version nibble (0..15), or -1 when the variant is not RFC:
 * outside RFC the nibble carries no version meaning. */
R_API int r_uuid_get_version(const RUuid *u);
R_API const char *r_uuid_variant_name(RUuidVariant v);

/* Lowercase 8-4-4-4-12. out_size must be >= R_UUID_STR_SIZE. */
R_API bool r_uuid_to_string(const RUuid *u, char *out, size_t out_size);
R_API RUuidFmt r_uuid_format_from_str(const char *fmt);
R_API bool r_uuid_format(const RUuid *u, RUuidFmt fmt, char *out, size_t out_size);
/* Accepts 8-4-4-4-12, optionally wrapped in {} or prefixed by "urn:uuid:".
 * Hex is case-insensitive. *u is left untouched on failure. */
R_API bool r_uuid_from_string(RUuid *u, const char *s);

/* memcmp-style result: <0, 0, >0. Bytewise, so v6/v7 sort by creation time. */
R_API int r_uuid_compare(const RUuid *a, const RUuid *b);
R_API bool r_uuid_is_nil(const RUuid *u);

/* Creation time in Unix milliseconds for v1, v6 and v7. false for others. */
R_API bool r_uuid_get_unix_ms(const RUuid *u, ut64 *out);

/* {"uuid":"..","variant":"rfc","version":7,"timestamp_ms":1645557742000}
 * version / timestamp_ms are present only when they are meaningful.
 * out_size should be >= R_UUID_JSON_MAX. */
R_API bool r_uuid_to_json(const RUuid *u, char *out, size_t out_size);

/* "dns", "url", "oid", "x500" -> RFC 9562 namespace UUID, else NULL. */
R_API const RUuid *r_uuid_namespace(const char *name);

/* ------------------------------------------------------------------ */
/* Pure builders: all inputs explicit, no clock, no randomness.        */
/* Trivial to test against RFC vectors.                                */
/* ------------------------------------------------------------------ */

/* ts100ns: 100ns ticks since 1582-10-15, must fit in 60 bits.
 * clock_seq: only the low 14 bits are used. */
R_API bool r_uuid_make_v1(RUuid *u, ut64 ts100ns, ut16 clock_seq, const ut8 node[6]);
/* v2 uses a 32-bit local identifier and 8-bit DCE domain in place of
 * the low timestamp and clock sequence fields. */
R_API bool r_uuid_make_v2(RUuid *u, ut64 ts100ns, ut8 clock_seq, ut8 domain, ut32 local_id, const ut8 node[6]);
R_API bool r_uuid_make_v6(RUuid *u, ut64 ts100ns, ut16 clock_seq, const ut8 node[6]);
/* v3 = MD5(ns || name), v5 = SHA-1(ns || name), deterministic. */
R_API bool r_uuid_make_v3(RUuid *u, const RUuid *ns, const ut8 *name, size_t len);
R_API bool r_uuid_make_v5(RUuid *u, const RUuid *ns, const ut8 *name, size_t len);
R_API bool r_uuid_make_v4(RUuid *u, const ut8 rnd[16]);
/* unix_ms must fit in 48 bits. rnd supplies rand_a / rand_b. */
R_API bool r_uuid_make_v7(RUuid *u, ut64 unix_ms, const ut8 rnd[10]);
/* v8 = vendor-specific: 122 bits are entirely yours. */
R_API bool r_uuid_make_v8(RUuid *u, const ut8 custom[16]);

/* ------------------------------------------------------------------ */
/* Generation with entropy sources, hooks and debug stubs              */
/* ------------------------------------------------------------------ */

typedef bool (*RUuidRandFn)(ut8 *buf, size_t len, void *user);
typedef ut64 (*RUuidNowFn)(void *user);                  /* Unix ms */
typedef bool (*RUuidCustomFn)(ut8 out[16], void *user);  /* your own v8 math */
typedef void (*RUuidAuditFn)(const RUuid *u, RUuidVersion v, void *user);

typedef struct {
	const ut8 *data;
	size_t len;
} RUuidEntropy;

/* Zero-initialisation is a valid "all defaults" value. */
typedef struct {
	/* base randomness; NULL = OS CSPRNG (or the fake one, see R_UUID_FAKE) */
	RUuidRandFn rand_fn;
	void *rand_user;
	/* clock; NULL = system clock (or the fake one) */
	RUuidNowFn now_fn;
	void *now_user;
	/* any number of extra entropy sources, mixed in with SHA-1.
	 * They are added to the base randomness, never replace it. */
	const RUuidEntropy *extra;
	size_t n_extra;
	/* v3 / v5 */
	const RUuid *ns;
	const ut8 *name;
	size_t name_len;
	/* v2: DCE security local domain (0=person, 1=group, 2=org) and ID */
	ut8 v2_domain;
	ut32 v2_local_id;
	/* v8: custom_fn wins over custom bytes, which win over random */
	RUuidCustomFn custom_fn;
	void *custom_user;
	const ut8 *custom; /* 16 bytes */
	/* called after every successfully generated UUID */
	RUuidAuditFn audit_fn;
	void *audit_user;
} RUuidOpts;

R_API void r_uuid_opts_init(RUuidOpts *o);

/* opts may be NULL (all defaults). On failure *out is not modified. */
R_API bool r_uuid_generate(RUuid *out, RUuidVersion v, const RUuidOpts *opts);
/* Returns how many were generated (stops at the first failure). */
R_API size_t r_uuid_generate_n(RUuid *out, size_t n, RUuidVersion v, const RUuidOpts *opts);

/* Deterministic stand-ins for tests and debugging.
 * r_uuid_fake_rand: user must point to a ut64 seed/state.
 * r_uuid_fake_now:  user must point to a ut64 ms counter, post-incremented. */
R_API bool r_uuid_fake_rand(ut8 *buf, size_t len, void *user);
R_API ut64 r_uuid_fake_now(void *user);

/* Generator table lookups. Names are "v1".."v8". */
R_API bool r_uuid_version_supported(RUuidVersion v);
R_API const char *r_uuid_version_name(RUuidVersion v);  /* NULL if unsupported */
R_API const char *r_uuid_version_desc(RUuidVersion v);  /* NULL if unsupported */
/* "v7", "V7" or "7" -> 7; -1 if unknown or unsupported */
R_API int r_uuid_version_from_name(const char *s);

#ifdef __cplusplus
}
#endif

#endif
