#include <r_util.h>
#include "minunit.h"

enum {
	CHUNK_XML = 0x0003,
	CHUNK_STRING_POOL = 0x0001,
	CHUNK_START_NAMESPACE = 0x0100,
	CHUNK_END_NAMESPACE = 0x0101,
	CHUNK_START_ELEMENT = 0x0102,
	CHUNK_END_ELEMENT = 0x0103,
};

typedef struct {
	ut8 bytes[1024];
	size_t size;
} AxmlBuf;

static void put16(AxmlBuf *b, ut16 v) {
	r_write_le16 (b->bytes + b->size, v);
	b->size += sizeof (ut16);
}

static void put32(AxmlBuf *b, ut32 v) {
	r_write_le32 (b->bytes + b->size, v);
	b->size += sizeof (ut32);
}

static void put_chunk(AxmlBuf *b, ut16 type, ut16 header_size, ut32 size) {
	put16 (b, type);
	put16 (b, header_size);
	put32 (b, size);
}

static void put_utf16(AxmlBuf *b, const char *s) {
	const size_t len = strlen (s);
	size_t i;
	put16 (b, (ut16)len);
	for (i = 0; i < len; i++) {
		put16 (b, (ut8)s[i]);
	}
	put16 (b, 0);
}

static void put_xml_header(AxmlBuf *b, ut32 size) {
	put_chunk (b, CHUNK_XML, 8, size);
}

// A pool chunk of `size` bytes only keeps room for (size - 20) / 4 offsets
static void put_small_string_pool(AxmlBuf *b, ut32 size, ut32 string_count) {
	const size_t start = b->size;
	put_chunk (b, CHUNK_STRING_POOL, 28, size);
	put32 (b, string_count);
	put32 (b, 0); // style_count
	put32 (b, 0); // flags, UTF-16
	put32 (b, 0); // strings_offset
	put32 (b, 0); // styles_offset
	while (b->size < start + size) {
		put32 (b, 0); // offsets[]
	}
}

static void put_start_element(AxmlBuf *b, ut32 size, ut32 name, ut16 attribute_count) {
	put_chunk (b, CHUNK_START_ELEMENT, 16, size);
	put32 (b, 0); // line
	put32 (b, 0); // comment
	put32 (b, 0); // namespace
	put32 (b, name);
	put32 (b, 0); // flags
	put16 (b, attribute_count);
	put16 (b, 0);
	put16 (b, 0);
	put16 (b, 0);
}

static void pad(AxmlBuf *b, size_t size) {
	b->size = size;
}

static const char *const manifest_strings[] = {
	"android",
	"http://schemas.android.com/apk/res/android",
	"manifest",
	"package",
	"com.example"
};

static void put_manifest_string_pool(AxmlBuf *b) {
	AxmlBuf strings = {{ 0 }, 0};
	ut32 offsets[R_ARRAY_SIZE (manifest_strings)];
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (manifest_strings); i++) {
		offsets[i] = strings.size;
		put_utf16 (&strings, manifest_strings[i]);
	}
	const ut32 strings_offset = (ut32)(28 + sizeof (offsets));
	put_chunk (b, CHUNK_STRING_POOL, 28, (ut32)(strings_offset + strings.size));
	put32 (b, (ut32)R_ARRAY_SIZE (manifest_strings));
	put32 (b, 0); // style_count
	put32 (b, 0); // flags, UTF-16
	put32 (b, strings_offset);
	put32 (b, 0); // styles_offset
	for (i = 0; i < R_ARRAY_SIZE (offsets); i++) {
		put32 (b, offsets[i]);
	}
	memcpy (b->bytes + b->size, strings.bytes, strings.size);
	b->size += strings.size;
}

static void put_manifest(AxmlBuf *b) {
	AxmlBuf body = {{ 0 }, 0};
	put_manifest_string_pool (&body);

	put_chunk (&body, CHUNK_START_NAMESPACE, 16, 24);
	put32 (&body, 1); // line
	put32 (&body, UT32_MAX); // comment
	put32 (&body, 0); // prefix, "android"
	put32 (&body, 1); // uri

	put_chunk (&body, CHUNK_START_ELEMENT, 16, 36 + 20);
	put32 (&body, 1); // line
	put32 (&body, UT32_MAX); // comment
	put32 (&body, UT32_MAX); // namespace
	put32 (&body, 2); // name, "manifest"
	put16 (&body, 20); // attribute start
	put16 (&body, 20); // attribute size
	put16 (&body, 1); // attribute count
	put16 (&body, 0);
	put16 (&body, 0);
	put16 (&body, 0);
	put32 (&body, UT32_MAX); // attribute namespace
	put32 (&body, 3); // attribute name, "package"
	put32 (&body, 4); // attribute raw value
	put16 (&body, 8); // value size
	put16 (&body, 0x0300); // unused and RESOURCE_STRING
	put32 (&body, 4); // value, "com.example"

	put_chunk (&body, CHUNK_END_ELEMENT, 16, 24);
	put32 (&body, 1);
	put32 (&body, UT32_MAX);
	put32 (&body, UT32_MAX);
	put32 (&body, 2);

	put_chunk (&body, CHUNK_END_NAMESPACE, 16, 24);
	put32 (&body, 1);
	put32 (&body, UT32_MAX);
	put32 (&body, 0);
	put32 (&body, 1);

	put_xml_header (b, (ut32)(8 + body.size));
	memcpy (b->bytes + b->size, body.bytes, body.size);
	b->size += body.size;
}

static bool test_axml_decode_manifest(void) {
	AxmlBuf b = {{ 0 }, 0};
	put_manifest (&b);
	char *s = r_axml_decode (b.bytes, b.size, NULL);
	mu_assert_notnull (s, "manifest must decode");
	mu_assert_streq_free (s, "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\""
		" package=\"com.example\">\n</manifest>\n", "decoded manifest");
	mu_end;
}

static bool test_axml_string_index_past_pool_chunk(void) {
	AxmlBuf b = {{ 0 }, 0};
	put_xml_header (&b, 80);
	// 32 byte pool chunk, but the file claims a million strings
	put_small_string_pool (&b, 32, 0x00100000);
	put_start_element (&b, 32, 4, 0);
	pad (&b, 80);
	char *s = r_axml_decode (b.bytes, b.size, NULL);
	mu_assert_notnull (s, "oversized string index must not read past the pool chunk");
	free (s);
	mu_end;
}

static bool test_axml_string_pool_chunk_too_small(void) {
	AxmlBuf b = {{ 0 }, 0};
	put_xml_header (&b, 80);
	// a 12 byte pool chunk does not even hold the pool header
	put_chunk (&b, CHUNK_STRING_POOL, 28, 12);
	put32 (&b, 4); // string_count
	put_start_element (&b, 32, 0, 0);
	pad (&b, 80);
	char *s = r_axml_decode (b.bytes, b.size, NULL);
	mu_assert_notnull (s, "truncated pool chunk must not be parsed as a pool header");
	free (s);
	mu_end;
}

static bool test_axml_element_chunk_too_small(void) {
	AxmlBuf b = {{ 0 }, 0};
	put_xml_header (&b, 80);
	put_small_string_pool (&b, 32, 4);
	// a 16 byte element chunk stops before attribute_count
	put_start_element (&b, 16, 0, 0);
	pad (&b, 80);
	char *s = r_axml_decode (b.bytes, b.size, NULL);
	mu_assert_null (s, "truncated element chunk must be rejected");
	mu_end;
}

static bool test_axml_attributes_past_element_chunk(void) {
	AxmlBuf b = {{ 0 }, 0};
	put_xml_header (&b, 120);
	put_small_string_pool (&b, 32, 4);
	// 48 bytes only hold the element header, not two 20 byte attributes
	put_start_element (&b, 48, 0, 2);
	pad (&b, 120);
	char *s = r_axml_decode (b.bytes, b.size, NULL);
	mu_assert_null (s, "attribute count must be bound by the element chunk");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_axml_decode_manifest);
	mu_run_test (test_axml_string_index_past_pool_chunk);
	mu_run_test (test_axml_string_pool_chunk_too_small);
	mu_run_test (test_axml_element_chunk_too_small);
	mu_run_test (test_axml_attributes_past_element_chunk);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
