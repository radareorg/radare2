#include <r_util/r_uuid.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int fails;

#define CHECK(c) do { \
		if (!(c)) { \
			fprintf (stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
			fails++; \
		} \
	} while (0)

static bool is(const RUuid *u, const char *expect) {
	char s[R_UUID_STR_SIZE];
	return r_uuid_to_string (u, s, sizeof (s)) && !strcmp (s, expect);
}

static const char *fmt_str(const RUuid *u, RUuidFmt f) {
	static char buf[R_UUID_STR_FMT_MAX];
	return r_uuid_format (u, f, buf, sizeof (buf)) ? buf : "(error)";
}

static void test_core(void) {
	RUuid u, v, keep, nil;
	char s[R_UUID_STR_SIZE];
	int i;
	memset (&nil, 0, sizeof (nil));

	CHECK (r_uuid_from_string (&u, "919108f7-52d1-4320-9bac-f847db4148a8"));
	CHECK (r_uuid_get_version (&u) == 4);
	CHECK (r_uuid_get_variant (&u) == R_UUID_VAR_RFC);
	CHECK (is (&u, "919108f7-52d1-4320-9bac-f847db4148a8"));

	CHECK (r_uuid_from_string (&v, "{017F22E2-79B0-7CC3-98C4-DC0C0C07398F}"));
	CHECK (r_uuid_get_version (&v) == 7);
	CHECK (r_uuid_from_string (&v, "urn:uuid:017f22e2-79b0-7cc3-98c4-dc0c0c07398f"));
	CHECK (r_uuid_compare (&v, &u) < 0);
	CHECK (r_uuid_compare (&u, &v) > 0);
	CHECK (r_uuid_compare (&u, &u) == 0);

	CHECK (r_uuid_is_nil (&nil) && !r_uuid_is_nil (&u));
	CHECK (r_uuid_get_version (&nil) == -1);
	CHECK (r_uuid_get_variant (&nil) == R_UUID_VAR_NCS);

	memset (&v, 0, sizeof (v));
	v.b[8] = 0xC5;
	CHECK (r_uuid_get_variant (&v) == R_UUID_VAR_MS);
	CHECK (r_uuid_get_version (&v) == -1);
	v.b[8] = 0xE0;
	CHECK (r_uuid_get_variant (&v) == R_UUID_VAR_FUTURE);

	/* set_variant / set_version round trip */
	memset (&v, 0xFF, sizeof (v));
	r_uuid_set_variant (&v, R_UUID_VAR_NCS);
	CHECK (r_uuid_get_variant (&v) == R_UUID_VAR_NCS);
	r_uuid_set_variant (&v, R_UUID_VAR_MS);
	CHECK (r_uuid_get_variant (&v) == R_UUID_VAR_MS);
	r_uuid_set_variant (&v, R_UUID_VAR_RFC);
	CHECK (r_uuid_get_variant (&v) == R_UUID_VAR_RFC);
	for (i = 1; i <= 8; i++) {
		r_uuid_set_version (&v, (RUuidVersion)i);
		CHECK (r_uuid_get_version (&v) == i);
	}

	/* bad input leaves the target untouched */
	{
		static const char *bad[] = {
			"", "919108f7-52d1-4320-9bac-f847db4148a",
			"919108f7152d1-4320-9bac-f847db4148a8",
			"919108f7-52d1-4320-9bac-f847db4148zz",
			"{919108f7-52d1-4320-9bac-f847db4148a8",
			"919108f7-52d1-4320-9bac-f847db4148a8 ", NULL
		};
		keep = u;
		for (i = 0; bad[i]; i++) {
			CHECK (!r_uuid_from_string (&u, bad[i]));
		}
		CHECK (!memcmp (&keep, &u, sizeof (u)));
		CHECK (!r_uuid_from_string (&u, NULL));
	}
	CHECK (!r_uuid_to_string (&u, s, 36));

	/* formats */
	CHECK (r_uuid_from_string (&u, "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"));
	CHECK (!strcmp (fmt_str (&u, R_UUID_FMT_STD), "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"));
	CHECK (!strcmp (fmt_str (&u, R_UUID_FMT_UPPER), "017F22E2-79B0-7CC3-98C4-DC0C0C07398F"));
	CHECK (!strcmp (fmt_str (&u, R_UUID_FMT_COMPACT), "017f22e279b07cc398c4dc0c0c07398f"));
	CHECK (!strcmp (fmt_str (&u, R_UUID_FMT_BRACES), "{017f22e2-79b0-7cc3-98c4-dc0c0c07398f}"));
	CHECK (!strcmp (fmt_str (&u, R_UUID_FMT_URN), "urn:uuid:017f22e2-79b0-7cc3-98c4-dc0c0c07398f"));
	CHECK (!r_uuid_format (&u, R_UUID_FMT_URN, s, 10));
	/* formats other than std must parse back, except compact (no dashes) */
	{
		RUuid back;
		CHECK (r_uuid_from_string (&back, fmt_str (&u, R_UUID_FMT_BRACES)) && !r_uuid_compare (&u, &back));
		CHECK (r_uuid_from_string (&back, fmt_str (&u, R_UUID_FMT_URN)) && !r_uuid_compare (&u, &back));
		CHECK (r_uuid_from_string (&back, fmt_str (&u, R_UUID_FMT_UPPER)) && !r_uuid_compare (&u, &back));
	}
}

static void test_builders(void) {
	RUuid u;
	static const ut8 v4rnd[16] = { 0x91, 0x91, 0x08, 0xf7, 0x52, 0xd1, 0x43, 0x20,
		0x9b, 0xac, 0xf8, 0x47, 0xdb, 0x41, 0x48, 0xa8 };
	/* RFC 9562 A.6: only the low bits of rnd[0], rnd[2] survive finalize */
	static const ut8 v7rnd[10] = { 0x0C, 0xC3, 0x18, 0xC4, 0xDC, 0x0C, 0x0C, 0x07, 0x39, 0x8F };
	static const ut8 v8c[16] = { 0x24, 0x89, 0xe9, 0xad, 0x2e, 0xe2, 0x8e, 0x00,
		0x8e, 0xc9, 0x32, 0xd5, 0xf6, 0x91, 0x81, 0xc0 };
	static const ut8 node[6] = { 0x9f, 0x6b, 0xde, 0xce, 0xd8, 0x46 };
	ut64 ms;

	CHECK (r_uuid_make_v4 (&u, v4rnd));
	CHECK (is (&u, "919108f7-52d1-4320-9bac-f847db4148a8"));

	CHECK (r_uuid_make_v7 (&u, 0x017F22E279B0ULL, v7rnd));
	CHECK (is (&u, "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"));
	CHECK (r_uuid_get_unix_ms (&u, &ms) && ms == 1645557742000ULL);
	CHECK (!r_uuid_make_v7 (&u, 1ULL << 48, v7rnd));

	CHECK (r_uuid_make_v8 (&u, v8c));
	CHECK (is (&u, "2489e9ad-2ee2-8e00-8ec9-32d5f69181c0"));

	/* RFC 9562 B.1 and B.2: same timestamp, v1 vs v6 */
	CHECK (r_uuid_make_v1 (&u, 0x1EC9414C232AB00ULL, 0x33C8, node));
	CHECK (is (&u, "c232ab00-9414-11ec-b3c8-9f6bdeced846"));
	CHECK (r_uuid_get_unix_ms (&u, &ms) && ms == 1645557742000ULL);
	CHECK (r_uuid_make_v2 (&u, 0x1EC9414C232AB00ULL, 0x3F, 0, 501, node));
	CHECK (is (&u, "000001f5-9414-21ec-bf00-9f6bdeced846"));
	CHECK (r_uuid_make_v6 (&u, 0x1EC9414C232AB00ULL, 0x33C8, node));
	CHECK (is (&u, "1ec9414c-232a-6b00-b3c8-9f6bdeced846"));
	CHECK (r_uuid_get_unix_ms (&u, &ms) && ms == 1645557742000ULL);
	CHECK (!r_uuid_make_v1 (&u, 1ULL << 60, 0, node));

	/* name-based, reference values from Python's uuid module */
	CHECK (r_uuid_make_v3 (&u, r_uuid_namespace ("dns"), (const ut8 *)"python.org", 10));
	CHECK (is (&u, "6fa459ea-ee8a-3ca4-894e-db77e160355e"));
	CHECK (r_uuid_make_v5 (&u, r_uuid_namespace ("dns"), (const ut8 *)"python.org", 10));
	CHECK (is (&u, "886313e1-3b8a-5372-9b90-0c9aee199e5d"));
	CHECK (r_uuid_make_v5 (&u, r_uuid_namespace ("dns"), (const ut8 *)"www.example.com", 15));
	CHECK (is (&u, "2ed6657d-e927-568b-95e1-2665a8aea6a2"));
	CHECK (r_uuid_make_v3 (&u, r_uuid_namespace ("url"), (const ut8 *)"", 0));
	CHECK (r_uuid_get_version (&u) == 3);
	/* names longer than one hash block */
	{
		char big[300];
		memset (big, 'a', sizeof (big));
		CHECK (r_uuid_make_v5 (&u, r_uuid_namespace ("oid"), (const ut8 *)big, sizeof (big)));
		CHECK (is (&u, "ef72bff2-933b-537c-9564-38fa2c1262a9"));
	}

	CHECK (!strcmp (fmt_str (r_uuid_namespace ("dns"), R_UUID_FMT_STD), "6ba7b810-9dad-11d1-80b4-00c04fd430c8"));
	CHECK (!strcmp (fmt_str (r_uuid_namespace ("url"), R_UUID_FMT_STD), "6ba7b811-9dad-11d1-80b4-00c04fd430c8"));
	CHECK (!strcmp (fmt_str (r_uuid_namespace ("oid"), R_UUID_FMT_STD), "6ba7b812-9dad-11d1-80b4-00c04fd430c8"));
	CHECK (!strcmp (fmt_str (r_uuid_namespace ("x500"), R_UUID_FMT_STD), "6ba7b814-9dad-11d1-80b4-00c04fd430c8"));
	CHECK (r_uuid_namespace ("nope") == NULL && r_uuid_namespace (NULL) == NULL);
}

static void test_json(void) {
	RUuid u;
	char out[R_UUID_JSON_MAX];
	char tiny[8];
	CHECK (r_uuid_from_string (&u, "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"));
	CHECK (r_uuid_to_json (&u, out, sizeof (out)));
	CHECK (!strcmp (out, "{\"uuid\":\"017f22e2-79b0-7cc3-98c4-dc0c0c07398f\",\"variant\":\"rfc\","
		"\"version\":7,\"timestamp_ms\":1645557742000}"));
	CHECK (r_uuid_from_string (&u, "919108f7-52d1-4320-9bac-f847db4148a8"));
	CHECK (r_uuid_to_json (&u, out, sizeof (out)));
	CHECK (!strcmp (out, "{\"uuid\":\"919108f7-52d1-4320-9bac-f847db4148a8\",\"variant\":\"rfc\",\"version\":4}"));
	memset (&u, 0, sizeof (u));
	CHECK (r_uuid_to_json (&u, out, sizeof (out)));
	CHECK (!strcmp (out, "{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"variant\":\"ncs\"}"));
	CHECK (!r_uuid_to_json (&u, tiny, sizeof (tiny)));
}

static int audit_count;
static void audit_cb(const RUuid *u, RUuidVersion v, void *user) {
	(void)u;
	(void)v;
	(*(int *)user)++;
}

static bool custom_cb(ut8 out[16], void *user) {
	int i;
	ut8 seed = *(ut8 *)user;
	for (i = 0; i < 16; i++) {
		out[i] = (ut8)(seed * (i + 1)); /* your own "math" goes here */
	}
	return true;
}

static void test_generation_deterministic(void) {
	RUuidOpts o;
	RUuid a, b, c, d, e;
	ut64 st = 1;
	ut64 t = 1645557742000ULL;
	ut64 ms;
	static const RUuidEntropy ex1[2] = { { (const ut8 *)"abc", 3 }, { (const ut8 *)"xyz", 3 } };
	static const RUuidEntropy ex2[2] = { { (const ut8 *)"xyz", 3 }, { (const ut8 *)"abc", 3 } };
	static const RUuidEntropy ex3[1] = { { (const ut8 *)"abcxyz", 6 } };
	RUuid arr[5];
	size_t i, j;

	r_uuid_opts_init (&o);
	o.rand_fn = r_uuid_fake_rand;
	o.rand_user = &st;

	/* same state -> same UUID */
	st = 1;
	CHECK (r_uuid_generate (&a, R_UUID_V4, &o));
	st = 1;
	CHECK (r_uuid_generate (&b, R_UUID_V4, &o));
	CHECK (!r_uuid_compare (&a, &b));
	CHECK (r_uuid_get_version (&a) == 4 && r_uuid_get_variant (&a) == R_UUID_VAR_RFC);

	/* extra entropy changes the result, deterministically, order-sensitive */
	o.extra = ex1;
	o.n_extra = 2;
	st = 1;
	CHECK (r_uuid_generate (&c, R_UUID_V4, &o));
	st = 1;
	CHECK (r_uuid_generate (&d, R_UUID_V4, &o));
	CHECK (r_uuid_compare (&a, &c) != 0);
	CHECK (!r_uuid_compare (&c, &d));
	CHECK (r_uuid_get_version (&c) == 4);
	o.extra = ex2;
	st = 1;
	CHECK (r_uuid_generate (&e, R_UUID_V4, &o));
	CHECK (r_uuid_compare (&c, &e) != 0);
	o.extra = ex3;
	o.n_extra = 1;
	st = 1;
	CHECK (r_uuid_generate (&e, R_UUID_V4, &o));
	CHECK (r_uuid_compare (&c, &e) != 0); /* ("abc","xyz") != ("abcxyz") */
	o.extra = NULL;
	CHECK (!r_uuid_generate (&e, R_UUID_V4, &o)); /* n_extra set but no array */
	o.n_extra = 0;

	/* time-based versions use the injected clock */
	o.now_fn = r_uuid_fake_now;
	o.now_user = &t;
	CHECK (r_uuid_generate (&a, R_UUID_V7, &o));
	CHECK (r_uuid_generate (&b, R_UUID_V7, &o));
	CHECK (r_uuid_get_unix_ms (&a, &ms) && ms == 1645557742000ULL);
	CHECK (r_uuid_get_unix_ms (&b, &ms) && ms == 1645557742001ULL);
	CHECK (r_uuid_compare (&a, &b) < 0);
	t = 1645557742000ULL;
	CHECK (r_uuid_generate (&a, R_UUID_V1, &o));
	CHECK (r_uuid_get_version (&a) == 1 && r_uuid_get_unix_ms (&a, &ms) && ms == 1645557742000ULL);
	CHECK ((a.b[10] & 0x01) == 0x01); /* random node => multicast bit set */
	t = 1645557742000ULL;
	CHECK (r_uuid_generate (&a, R_UUID_V6, &o));
	CHECK (r_uuid_get_version (&a) == 6 && r_uuid_get_unix_ms (&a, &ms) && ms == 1645557742000ULL);

	/* name-based through the generic entry point */
	o.ns = r_uuid_namespace ("dns");
	o.name = (const ut8 *)"python.org";
	o.name_len = 10;
	CHECK (r_uuid_generate (&a, R_UUID_V5, &o));
	CHECK (is (&a, "886313e1-3b8a-5372-9b90-0c9aee199e5d"));
	CHECK (r_uuid_generate (&a, R_UUID_V3, &o));
	CHECK (is (&a, "6fa459ea-ee8a-3ca4-894e-db77e160355e"));
	o.ns = NULL;
	CHECK (!r_uuid_generate (&a, R_UUID_V5, &o));
	o.ns = r_uuid_namespace ("dns");
	o.name = NULL;
	o.name_len = 3;
	CHECK (!r_uuid_generate (&a, R_UUID_V5, &o));

	/* failure must not modify the output */
	memset (&a, 0x5A, sizeof (a));
	b = a;
	CHECK (!r_uuid_generate (&a, R_UUID_V5, &o));
	CHECK (!memcmp (&a, &b, sizeof (a)));

	/* v8: custom function, then custom bytes, then derived */
	{
		ut8 seed = 3;
		RUuidOpts o8;
		static const ut8 cbytes[16] = { 0 };
		r_uuid_opts_init (&o8);
		o8.custom_fn = custom_cb;
		o8.custom_user = &seed;
		CHECK (r_uuid_generate (&a, R_UUID_V8, &o8));
		CHECK (r_uuid_get_version (&a) == 8 && a.b[0] == 3 && a.b[1] == 6);
		o8.custom_fn = NULL;
		o8.custom = cbytes;
		CHECK (r_uuid_generate (&a, R_UUID_V8, &o8));
		CHECK (a.b[6] == 0x80 && a.b[8] == 0x80 && a.b[0] == 0);
	}

	/* v2 DCE security */
	r_uuid_opts_init (&o);
	o.rand_fn = r_uuid_fake_rand;
	o.rand_user = &st;
	o.now_fn = r_uuid_fake_now;
	t = 1645557742000ULL;
	o.now_user = &t;
	o.v2_domain = 1;
	o.v2_local_id = 123;
	CHECK (r_uuid_generate (&a, R_UUID_V2, &o));
	CHECK (r_uuid_get_version (&a) == 2 && a.b[3] == 123 && a.b[9] == 1);

	/* unsupported versions */
	CHECK (!r_uuid_generate (&a, R_UUID_V0, &o));
	CHECK (!r_uuid_generate (NULL, R_UUID_V4, &o));

	/* audit hook + batch */
	r_uuid_opts_init (&o);
	o.rand_fn = r_uuid_fake_rand;
	o.rand_user = &st;
	o.audit_fn = audit_cb;
	o.audit_user = &audit_count;
	audit_count = 0;
	CHECK (r_uuid_generate_n (arr, 5, R_UUID_V4, &o) == 5);
	CHECK (audit_count == 5);
	for (i = 0; i < 5; i++) {
		for (j = i + 1; j < 5; j++) {
			CHECK (r_uuid_compare (&arr[i], &arr[j]) != 0);
		}
	}
	/* a failing rand_fn stops the batch */
	o.rand_user = NULL; /* fake_rand returns false without state */
	CHECK (r_uuid_generate_n (arr, 5, R_UUID_V4, &o) == 0);

	/* version name lookups */
	CHECK (r_uuid_version_from_name ("v7") == 7);
	CHECK (r_uuid_version_from_name ("V7") == 7);
	CHECK (r_uuid_version_from_name ("4") == 4);
	CHECK (r_uuid_version_from_name ("v2") == 2);
	CHECK (r_uuid_version_from_name ("v16") == -1);
	CHECK (r_uuid_version_from_name ("v") == -1);
	CHECK (r_uuid_version_from_name ("") == -1);
	CHECK (r_uuid_version_from_name ("x7") == -1);
	CHECK (r_uuid_version_from_name (NULL) == -1);
	CHECK (r_uuid_version_name (R_UUID_V7) && !strcmp (r_uuid_version_name (R_UUID_V7), "v7"));
	CHECK (r_uuid_version_name (R_UUID_V2) && !strcmp (r_uuid_version_name (R_UUID_V2), "v2"));
	CHECK (r_uuid_version_supported (R_UUID_V4) && !r_uuid_version_supported (R_UUID_V_MAX));
}

#ifndef R_UUID_FAKE
/* Real OS sources. Skipped in a -DR_UUID_FAKE build, where output is fixed. */
static void test_generation_os(void) {
	enum { N = 2000 };
	static RUuid list[N];
	RUuidOpts o;
	size_t i, j;
	ut64 ms;
	ut64 now = (ut64)time (NULL) * 1000ULL;
	static const int vers[] = { 1, 4, 6, 7, 8 };
	size_t vi;

	for (vi = 0; vi < sizeof (vers) / sizeof (vers[0]); vi++) {
		RUuidVersion v = (RUuidVersion)vers[vi];
		CHECK (r_uuid_generate_n (list, N, v, NULL) == N);
		for (i = 0; i < N; i++) {
			CHECK (r_uuid_get_version (&list[i]) == (int)v);
			CHECK (r_uuid_get_variant (&list[i]) == R_UUID_VAR_RFC);
			if (v == R_UUID_V1 || v == R_UUID_V6 || v == R_UUID_V7) {
				CHECK (r_uuid_get_unix_ms (&list[i], &ms));
				CHECK (ms + 10000 > now && ms < now + 10000);
			}
		}
		for (i = 0; i < N; i += 7) { /* sampled O(n^2) uniqueness check */
			for (j = i + 1; j < N; j++) {
				if (!r_uuid_compare (&list[i], &list[j])) {
					fprintf (stderr, "FAIL duplicate for v%d\n", (int)v);
					fails++;
				}
			}
		}
	}

	/* a single run mixes real randomness with a user entropy source */
	r_uuid_opts_init (&o);
	{
		static const RUuidEntropy ex = { (const ut8 *)"user data", 9 };
		RUuid a, b;
		o.extra = &ex;
		o.n_extra = 1;
		CHECK (r_uuid_generate (&a, R_UUID_V4, &o));
		CHECK (r_uuid_generate (&b, R_UUID_V4, &o));
		CHECK (r_uuid_compare (&a, &b) != 0); /* base randomness still dominates */
		CHECK (r_uuid_get_version (&a) == 4);
	}
}
#endif

int main(void) {
	test_core ();
	test_builders ();
	test_json ();
	test_generation_deterministic ();
#ifndef R_UUID_FAKE
	test_generation_os ();
#endif
	if (fails) {
		fprintf (stderr, "%d check(s) failed\n", fails);
		return 1;
	}
	puts ("all ok");
	return 0;
}
