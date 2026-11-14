#include <r_util/r_uuid.h>
#include <stdio.h>
#include <string.h>

static const char hexdig[] = "0123456789abcdef";

static const RUuid ns_dns = {{ 0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 }};
static const RUuid ns_url = {{ 0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 }};
static const RUuid ns_oid = {{ 0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 }};
static const RUuid ns_x500 = {{ 0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 }};

static int hexval(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static ut32 be32(const ut8 *p) {
	return ((ut32)p[0] << 24) | ((ut32)p[1] << 16) | ((ut32)p[2] << 8) | (ut32)p[3];
}

static ut32 be16(const ut8 *p) {
	return ((ut32)p[0] << 8) | (ut32)p[1];
}

/* ---------------------------- bits ---------------------------- */

R_API void r_uuid_set_version(RUuid *u, RUuidVersion v) {
	u->b[6] = (ut8)((u->b[6] & 0x0F) | ((v & 0x0F) << 4));
}

R_API void r_uuid_set_variant(RUuid *u, RUuidVariant v) {
	switch (v) {
	case R_UUID_VAR_NCS:
		u->b[8] &= 0x7F;
		break;
	case R_UUID_VAR_RFC:
		u->b[8] = (ut8)((u->b[8] & 0x3F) | 0x80);
		break;
	case R_UUID_VAR_MS:
		u->b[8] = (ut8)((u->b[8] & 0x1F) | 0xC0);
		break;
	case R_UUID_VAR_FUTURE:
		u->b[8] |= 0xE0;
		break;
	default:
		break;
	}
}

R_API void r_uuid_finalize(RUuid *u, RUuidVersion v, RUuidVariant var) {
	r_uuid_set_version(u, v);
	r_uuid_set_variant(u, var);
}

R_API RUuidVariant r_uuid_get_variant(const RUuid *u) {
	const ut8 b = u->b[8];
	if (!(b & 0x80)) {
		return R_UUID_VAR_NCS;
	}
	if ((b & 0xC0) == 0x80) {
		return R_UUID_VAR_RFC;
	}
	if ((b & 0xE0) == 0xC0) {
		return R_UUID_VAR_MS;
	}
	return R_UUID_VAR_FUTURE;
}

R_API int r_uuid_get_version(const RUuid *u) {
	if (r_uuid_get_variant(u) != R_UUID_VAR_RFC) {
		return -1;
	}
	return u->b[6] >> 4;
}

R_API const char *r_uuid_variant_name(RUuidVariant v) {
	switch (v) {
	case R_UUID_VAR_NCS:
		return "ncs";
	case R_UUID_VAR_RFC:
		return "rfc";
	case R_UUID_VAR_MS:
		return "microsoft";
	case R_UUID_VAR_FUTURE:
		return "future";
	case R_UUID_VAR_MAX:
		break;
	}
	return "unknown";
}

/* ---------------------------- text ---------------------------- */

R_API bool r_uuid_to_string(const RUuid *u, char *out, size_t out_size) {
	if (!u || !out || out_size < R_UUID_STR_SIZE) {
		return false;
	}
	char *p = out;
	int i;
	for (i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10) {
			*p++ = '-';
		}
		*p++ = hexdig[u->b[i] >> 4];
		*p++ = hexdig[u->b[i] & 0x0F];
	}
	*p = '\0';
	return true;
}

R_API RUuidFmt r_uuid_format_from_str(const char *fmt) {
	if (!fmt) {
		return R_UUID_FMT_MAX;
	}
	if (!strcmp (fmt, "std")) {
		return R_UUID_FMT_STD;
	} else if (!strcmp (fmt, "upper")) {
		return R_UUID_FMT_UPPER;
	} else if (!strcmp (fmt, "compact")) {
		return R_UUID_FMT_COMPACT;
	} else if (!strcmp (fmt, "braces")) {
		return R_UUID_FMT_BRACES;
	} else if (!strcmp (fmt, "urn")) {
		return R_UUID_FMT_URN;
	} else {
		return R_UUID_FMT_MAX;
	}
}

R_API bool r_uuid_format(const RUuid *u, RUuidFmt fmt, char *out, size_t out_size) {
	char s[R_UUID_STR_SIZE];
	const char *pre = "";
	const char *post = "";
	bool upper = false;
	bool strip = false;

	if (!u || !out || !r_uuid_to_string(u, s, sizeof (s))) {
		return false;
	}
	switch (fmt) {
	case R_UUID_FMT_STD:
		break;
	case R_UUID_FMT_UPPER:
		upper = true;
		break;
	case R_UUID_FMT_COMPACT:
		strip = true;
		break;
	case R_UUID_FMT_BRACES:
		pre = "{";
		post = "}";
		break;
	case R_UUID_FMT_URN:
		pre = "urn:uuid:";
		break;
	default:
		return false;
	}
	size_t need = strlen(pre) + (strip ? 32 : R_UUID_STR_LEN) + strlen(post) + 1;
	if (out_size < need) {
		return false;
	}
	char *p = out;
	const char *q;
	for (q = pre; *q; q++) {
		*p++ = *q;
	}
	for (q = s; *q; q++) {
		char c = *q;
		if (strip && c == '-') {
			continue;
		}
		if (upper && c >= 'a' && c <= 'f') {
			c = (char)(c - 'a' + 'A');
		}
		*p++ = c;
	}
	for (q = post; *q; q++) {
		*p++ = *q;
	}
	*p = '\0';
	return true;
}

R_API bool r_uuid_from_string(RUuid *u, const char *s) {
	if (!u || !s) {
		return false;
	}
	size_t len = strlen(s);
	if (len >= 9 && !strncmp (s, "urn:uuid:", 9)) {
		s += 9;
		len -= 9;
	} else if (len >= 2 && s[0] == '{' && s[len - 1] == '}') {
		s++;
		len -= 2;
	}
	if (len != R_UUID_STR_LEN) {
		return false;
	}
	ut8 tmp[16];
	int bi = 0;
	size_t i = 0;
	while (i < R_UUID_STR_LEN) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (s[i] != '-') {
				return false;
			}
			i++;
			continue;
		}
		int hi = hexval(s[i]);
		int lo = hexval(s[i + 1]);
		if (hi < 0 || lo < 0) {
			return false;
		}
		tmp[bi++] = (ut8)((hi << 4) | lo);
		i += 2;
	}
	memcpy(u->b, tmp, sizeof (tmp));
	return true;
}

/* ------------------------- compare / info ------------------------- */

R_API int r_uuid_compare(const RUuid *a, const RUuid *b) {
	int r = memcmp (a->b, b->b, sizeof (a->b));
	return (r > 0) - (r < 0);
}

R_API bool r_uuid_is_nil(const RUuid *u) {
	int i;
	for (i = 0; i < 16; i++) {
		if (u->b[i]) {
			return false;
		}
	}
	return true;
}

R_API bool r_uuid_get_unix_ms(const RUuid *u, ut64 *out) {
	if (!u || !out) {
		return false;
	}
	ut64 ts;
	switch (r_uuid_get_version(u)) {
	case 7:
		*out = ((ut64)be32(u->b) << 16) | be16(u->b + 4);
		return true;
	case 1:
		ts = ((ut64)(be16(u->b + 6) & 0x0FFF) << 48)
			| ((ut64)be16(u->b + 4) << 32)
			| (ut64)be32(u->b);
		break;
	case 6:
		ts = ((ut64)be32(u->b) << 28)
			| ((ut64)be16(u->b + 4) << 12)
			| (ut64)(be16(u->b + 6) & 0x0FFF);
		break;
	default:
		return false;
	}
	if (ts < R_UUID_GREGORIAN_OFFSET) {
		return false; /* before 1970, not representable as Unix ms */
	}
	*out = (ts - R_UUID_GREGORIAN_OFFSET) / 10000ULL;
	return true;
}

R_API bool r_uuid_to_json(const RUuid *u, char *out, size_t out_size) {
	char s[R_UUID_STR_SIZE];
	size_t off = 0;
	int n;
	ut64 ms;
	int ver;

	if (!u || !out || !out_size || !r_uuid_to_string(u, s, sizeof (s))) {
		return false;
	}
#define APPEND(...) do { \
		if (off >= out_size) { \
			return false; \
		} \
		n = snprintf (out + off, out_size - off, __VA_ARGS__); \
		if (n < 0 || (size_t)n >= out_size - off) { \
			return false; \
		} \
		off += (size_t)n; \
	} while (0)

	APPEND ("{\"uuid\":\"%s\",\"variant\":\"%s\"", s, r_uuid_variant_name (r_uuid_get_variant (u)));
	ver = r_uuid_get_version (u);
	if (ver >= 0) {
		APPEND (",\"version\":%d", ver);
	}
	if (r_uuid_get_unix_ms (u, &ms)) {
		APPEND (",\"timestamp_ms\":%llu", (unsigned long long)ms);
	}
	APPEND ("}");
#undef APPEND
	return true;
}

R_API const RUuid *r_uuid_namespace(const char *name) {
	if (!name) {
		return NULL;
	}
	if (!strcmp (name, "dns")) {
		return &ns_dns;
	}
	if (!strcmp (name, "url")) {
		return &ns_url;
	}
	if (!strcmp (name, "oid")) {
		return &ns_oid;
	}
	if (!strcmp (name, "x500")) {
		return &ns_x500;
	}
	return NULL;
}
