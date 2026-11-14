/* ruuid: command-line front end for the r_uuid library.
 * Deliberately thin: every feature here is one call into r_uuid.h. */

#include <r_util/r_uuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EXTRA 32

static void usage(FILE *f) {
	fputs (
		"usage: ruuid [options]\n"
		"  -v VER     version: v1 v3 v4 v5 v6 v7 v8 (default v4)\n"
		"  -n COUNT   how many UUIDs to generate (default 1)\n"
		"  -f FMT     std | upper | compact | braces | urn (default std)\n"
		"  -j         JSON output (always std text form; array if COUNT > 1)\n"
		"  -N NS      namespace for v3/v5: dns | url | oid | x500 | <uuid>\n"
		"  -s NAME    name for v3/v5\n"
		"  -e TEXT    extra entropy source, may be repeated (up to 32)\n"
		"  -p UUID    parse and describe a UUID instead of generating\n"
		"  -l         list supported versions\n"
		"  -h         this help\n", f);
}

static bool parse_fmt(const char *s, RUuidFmt *out) {
	static const struct {
		const char *name;
		RUuidFmt fmt;
	} t[] = {
		{ "std", R_UUID_FMT_STD }, { "upper", R_UUID_FMT_UPPER },
		{ "compact", R_UUID_FMT_COMPACT }, { "braces", R_UUID_FMT_BRACES },
		{ "urn", R_UUID_FMT_URN }
	};
	size_t i;
	for (i = 0; i < sizeof (t) / sizeof (t[0]); i++) {
		if (!strcmp (s, t[i].name)) {
			*out = t[i].fmt;
			return true;
		}
	}
	return false;
}

static int describe(const char *text, bool json) {
	RUuid u;
	char buf[R_UUID_JSON_MAX];
	ut64 ms;
	int ver;

	if (!r_uuid_from_string (&u, text)) {
		fprintf (stderr, "ruuid: not a valid UUID: %s\n", text);
		return 1;
	}
	if (json) {
		if (!r_uuid_to_json (&u, buf, sizeof (buf))) {
			return 1;
		}
		puts (buf);
		return 0;
	}
	r_uuid_to_string (&u, buf, sizeof (buf));
	ver = r_uuid_get_version (&u);
	printf ("%s variant=%s", buf, r_uuid_variant_name (r_uuid_get_variant (&u)));
	if (ver >= 0) {
		printf (" version=%d", ver);
	}
	if (r_uuid_is_nil (&u)) {
		printf (" nil");
	}
	if (r_uuid_get_unix_ms (&u, &ms)) {
		printf (" timestamp_ms=%llu", (unsigned long long)ms);
	}
	putchar ('\n');
	return 0;
}

int main(int argc, char **argv) {
	int ver = 4;
	unsigned long count = 1;
	bool json = false;
	RUuidFmt fmt = R_UUID_FMT_STD;
	const char *ns_arg = NULL;
	const char *name = NULL;
	const char *parse = NULL;
	bool list = false;
	RUuidEntropy extra[MAX_EXTRA];
	size_t n_extra = 0;
	RUuid ns_buf;
	int i;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		const char *val = NULL;
		bool takes_arg = !strcmp (a, "-v") || !strcmp (a, "-n") || !strcmp (a, "-f")
			|| !strcmp (a, "-N") || !strcmp (a, "-s") || !strcmp (a, "-e") || !strcmp (a, "-p");
		if (takes_arg) {
			if (i + 1 >= argc) {
				fprintf (stderr, "ruuid: option %s needs a value\n", a);
				return 2;
			}
			val = argv[++i];
		}
		if (!strcmp (a, "-h")) {
			usage (stdout);
			return 0;
		} else if (!strcmp (a, "-j")) {
			json = true;
		} else if (!strcmp (a, "-l")) {
			list = true;
		} else if (!strcmp (a, "-v")) {
			ver = r_uuid_version_from_name (val);
			if (ver < 0) {
				fprintf (stderr, "ruuid: unsupported version: %s (see -l)\n", val);
				return 2;
			}
		} else if (!strcmp (a, "-n")) {
			char *end = NULL;
			count = strtoul (val, &end, 10);
			if (!*val || *end || !count) {
				fprintf (stderr, "ruuid: bad count: %s\n", val);
				return 2;
			}
		} else if (!strcmp (a, "-f")) {
			if (!parse_fmt (val, &fmt)) {
				fprintf (stderr, "ruuid: unknown format: %s\n", val);
				return 2;
			}
		} else if (!strcmp (a, "-N")) {
			ns_arg = val;
		} else if (!strcmp (a, "-s")) {
			name = val;
		} else if (!strcmp (a, "-e")) {
			if (n_extra >= MAX_EXTRA) {
				fprintf (stderr, "ruuid: too many -e sources (max %d)\n", MAX_EXTRA);
				return 2;
			}
			extra[n_extra].data = (const ut8 *)val;
			extra[n_extra].len = strlen (val);
			n_extra++;
		} else if (!strcmp (a, "-p")) {
			parse = val;
		} else {
			fprintf (stderr, "ruuid: unknown option: %s\n", a);
			usage (stderr);
			return 2;
		}
	}

	if (list) {
		int v;
		for (v = 0; v <= R_UUID_V_MAX; v++) {
			const char *n = r_uuid_version_name ((RUuidVersion)v);
			if (n) {
				printf ("%-3s %s\n", n, r_uuid_version_desc ((RUuidVersion)v));
			}
		}
		return 0;
	}
	if (parse) {
		return describe (parse, json);
	}

	RUuidOpts o;
	r_uuid_opts_init (&o);
	o.extra = n_extra ? extra : NULL;
	o.n_extra = n_extra;
	if (ver == R_UUID_V3 || ver == R_UUID_V5) {
		if (!ns_arg || !name) {
			fprintf (stderr, "ruuid: v%d needs both -N and -s\n", ver);
			return 2;
		}
		o.ns = r_uuid_namespace (ns_arg);
		if (!o.ns) {
			if (!r_uuid_from_string (&ns_buf, ns_arg)) {
				fprintf (stderr, "ruuid: bad namespace: %s\n", ns_arg);
				return 2;
			}
			o.ns = &ns_buf;
		}
		o.name = (const ut8 *)name;
		o.name_len = strlen (name);
	}

	if (json && count > 1) {
		putchar ('[');
	}
	unsigned long k;
	for (k = 0; k < count; k++) {
		RUuid u;
		char buf[R_UUID_JSON_MAX];
		if (!r_uuid_generate (&u, (RUuidVersion)ver, &o)) {
			fprintf (stderr, "ruuid: generation failed\n");
			return 1;
		}
		if (json) {
			if (!r_uuid_to_json (&u, buf, sizeof (buf))) {
				return 1;
			}
			if (count > 1 && k) {
				putchar (',');
			}
			fputs (buf, stdout);
			if (count == 1) {
				putchar ('\n');
			}
		} else {
			if (!r_uuid_format (&u, fmt, buf, sizeof (buf))) {
				return 1;
			}
			puts (buf);
		}
	}
	if (json && count > 1) {
		puts ("]");
	}
	return 0;
}
