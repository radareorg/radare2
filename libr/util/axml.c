/* radare2 - LGPL - Copyright 2021-2022 - keegan */

#include <r_util.h>
#include "axml_resources.h"

// R2R db/formats/axml

enum {
	TYPE_STRING_POOL = 0x0001,
	TYPE_XML = 0x0003,
	TYPE_START_NAMESPACE = 0x100,
	TYPE_END_NAMESPACE = 0x101,
	TYPE_START_ELEMENT = 0x0102,
	TYPE_END_ELEMENT = 0x103,
	TYPE_RESOURCE_MAP = 0x180,
};

enum {
	RESOURCE_NULL = 0x00,
	RESOURCE_REFERENCE = 0x01,
	RESOURCE_STRING = 0x03,
	RESOURCE_FLOAT = 0x04,
	RESOURCE_INT_DEC = 0x10,
	RESOURCE_INT_HEX = 0x11,
	RESOURCE_BOOL = 0x12,
};

enum {
	FLAG_UTF8 = 1 << 8,
};

// Beginning of every header
R_PACKED(
	typedef struct {
		ut16 type;
		ut16 header_size;
		ut32 size;
	})
chunk_header_t;

// String pool referenced throughout the Binary XML, there must only be ONE
R_PACKED(
	typedef struct {
		chunk_header_t header;
		ut32 string_count;
		ut32 style_count;
		ut32 flags;
		ut32 strings_offset;
		ut32 styles_offset;
	})
string_pool_t;

R_PACKED(
	typedef struct {
		ut16 size;
		ut8 unused;
		ut8 type;
		union {
			ut32 d;
			float f;
		} data;
	})
resource_value_t;

R_PACKED(
	typedef struct {
		ut32 namespace;
		ut32 name;
		ut32 unused;
		resource_value_t value;
	})
attribute_t;

R_PACKED(
	typedef struct {
		ut32 namespace;
		ut32 name;
		ut16 attribute_start;
		ut16 attribute_size;
		ut16 attribute_count;
		ut16 unused0;
		ut16 unused1;
		ut16 unused2;
	})
start_element_t;

R_PACKED(
	typedef struct {
		ut32 namespace;
		ut32 name;
	})
end_element_t;

R_PACKED(
	typedef struct {
		ut32 prefix;
		ut32 uri;
	})
namespace_t;

// Borrow validated UTF-8 strings; convert UTF-16 into the caller's buffer.
static const char *string_lookup(const string_pool_t *pool, ut32 i, RStrBuf *sb) {
	if (i >= r_read_le32 (&pool->string_count)) {
		return NULL;
	}
	const ut8 *data = (const ut8 *)pool;
	ut32 strings_offset = r_read_le32 (&pool->strings_offset);
	ut32 end = r_read_le32 (&pool->styles_offset);
	if (!end) {
		end = r_read_le32 (&pool->header.size);
	}
	ut32 offset = r_read_le32 (data + r_read_le16 (&pool->header.header_size) + (size_t)i * sizeof (ut32));
	if (offset >= end - strings_offset) {
		return NULL;
	}
	RStrs string = r_strs_new ((const char *)data + strings_offset + offset, (const char *)data + end);
	ut32 n;
	if (r_read_le32 (&pool->flags) & FLAG_UTF8) {
		// The UTF-16 length precedes the UTF-8 byte length.
		int j;
		for (j = 0; j < 2; j++) {
			if (!r_strs_advance (&string, 1)) {
				return NULL;
			}
			n = (ut8)string.a[-1];
			if (n & 0x80) {
				if (!r_strs_advance (&string, 1)) {
					return NULL;
				}
				n = ((n & 0x7f) << 8) | (ut8)string.a[-1];
			}
		}
		if (n >= r_strs_len (string) || string.a[n]) {
			return NULL;
		}
		return string.a;
	}
	if (!r_strs_advance (&string, sizeof (ut16))) {
		return NULL;
	}
	n = r_read_le16 (string.a - sizeof (ut16));
	if (n & 0x8000) {
		if (!r_strs_advance (&string, sizeof (ut16))) {
			return NULL;
		}
		n = ((n & 0x7fff) << 16) | r_read_le16 (string.a - sizeof (ut16));
	}
	size_t remaining = r_strs_len (string);
	if (remaining < sizeof (ut16) || n > (remaining - sizeof (ut16)) / sizeof (ut16)) {
		return NULL;
	}
	size_t bytes = (size_t)n * sizeof (ut16);
	size_t capacity;
	if (r_read_le16 (string.a + bytes) || r_mul_overflow_size_t (n, 3, &capacity)
		|| r_add_overflow_size_t (capacity, 1, &capacity) || capacity > INT_MAX || bytes > INT_MAX
		|| !r_strbuf_reserve (sb, capacity - 1)) {
		return NULL;
	}
	char *name = r_strbuf_get (sb);
	int length = r_str_utf16_to_utf8 ((ut8 *)name, capacity, (const ut8 *)string.a, bytes, false);
	if (length < 0) {
		return NULL;
	}
	sb->len = length;
	return name;
}

static const char *resource_value(const string_pool_t *pool, const resource_value_t *value, RStrBuf *sb) {
	switch (value->type) {
	case RESOURCE_NULL:
		return "";
	case RESOURCE_REFERENCE:
		return r_strbuf_setf (sb, "@0x%x", value->data.d);
	case RESOURCE_STRING:
		return string_lookup (pool, r_read_le32 (&value->data.d), sb);
	case RESOURCE_FLOAT:
		return r_strbuf_setf (sb, "%f", value->data.f);
	case RESOURCE_INT_DEC:
		return r_strbuf_setf (sb, "%d", value->data.d);
	case RESOURCE_INT_HEX:
		return r_strbuf_setf (sb, "0x%x", value->data.d);
	case RESOURCE_BOOL:
		return value->data.d? "true": "false";
	default:
		R_LOG_WARN ("Resource type is not recognized: %#x", value->type);
		break;
	}
	return "null";
}

static bool dump_element(PJ *pj, RStrBuf *sb, const string_pool_t *pool, const namespace_t *namespace, const void *element, size_t element_size, const ut8 *resource_map, ut32 resource_map_length, st32 depth, bool start) {
	ut32 i;

	if (element_size < (start? sizeof (start_element_t): sizeof (end_element_t))) {
		R_LOG_ERROR ("Truncated element");
		return false;
	}

	RStrBuf keybuf = {0}, valuebuf = {0}, nsbuf = {0}, qualified = {0};
	bool ok = false;
	const end_element_t *common = element;
	const char *name = string_lookup (pool, r_read_le32 (&common->name), &keybuf);
	const char *ns = NULL;
	if (!name) {
		goto done;
	}
	r_strbuf_pad (sb, '\t', depth);
	r_strbuf_appendf (sb, "<%s%s", start? "": "/", name);

	if (start) {
		const start_element_t *e = element;
		ut16 count = r_read_le16 (&e->attribute_count);
		ut16 attribute_start = r_read_le16 (&e->attribute_start);
		ut16 attribute_size = r_read_le16 (&e->attribute_size);
		if (attribute_start < sizeof (*e) || attribute_start > element_size || attribute_size < sizeof (attribute_t)
			|| count > (element_size - attribute_start) / attribute_size) {
			R_LOG_ERROR ("Invalid element count");
			goto done;
		}
		if (pj) {
			pj_o (pj);
			pj_ko (pj, name);
		}
		if (depth == 0 && namespace) {
			ns = string_lookup (pool, r_read_le32 (&namespace->prefix), &nsbuf);
			const char *uri = string_lookup (pool, r_read_le32 (&namespace->uri), &valuebuf);
			if (!ns || !uri) {
				goto done;
			}
			if (pj) {
				pj_ko (pj, "xmlns");
				pj_ks (pj, ns, uri);
				pj_end (pj);
			}
			r_strbuf_appendf (sb, " xmlns:%s=\"%s\"", ns, uri);
		}

		for (i = 0; i < count; i++) {
			const attribute_t *a = (const attribute_t *)((const ut8 *)e + attribute_start + (size_t)i * attribute_size);
			ut32 key_index = r_read_le32 (&a->name);
			const char *key = string_lookup (pool, key_index, &keybuf);
			if (!key) {
				goto done;
			}
			// If the key is empty, it is a cached resource name
			if (!*key && resource_map && key_index < resource_map_length) {
				ut32 resource = r_read_le32 (resource_map + (size_t)key_index * sizeof (ut32));
				if (resource >= 0x1010000 && resource - 0x1010000 < ANDROID_ATTRIBUTE_NAMES_SIZE) {
					key = ANDROID_ATTRIBUTE_NAMES[resource - 0x1010000];
				}
			}
			if (!*key) {
				key = "null";
			}
			const char *value = resource_value (pool, &a->value, &valuebuf);
			if (!value) {
				goto done;
			}
			// Assume the active namespace also applies to this attribute.
			if (r_read_le32 (&a->namespace) != UT32_MAX && namespace && r_read_le32 (&namespace->prefix) != UT32_MAX) {
				if (!ns) {
					ns = string_lookup (pool, r_read_le32 (&namespace->prefix), &nsbuf);
				}
				if (!ns) {
					goto done;
				}
				key = r_strbuf_setf (&qualified, "%s:%s", ns, key);
				if (!key) {
					goto done;
				}
			}
			r_strbuf_appendf (sb, " %s=\"%s\"", key, value);
			if (pj) {
				pj_ks (pj, key, value);
			}
		}
	}

	r_strbuf_append (sb, ">\n");
	if (pj) {
		pj_end (pj);
	}
	ok = true;
done:
	r_strbuf_fini (&keybuf);
	r_strbuf_fini (&valuebuf);
	r_strbuf_fini (&nsbuf);
	r_strbuf_fini (&qualified);
	return ok;
}

R_API char *r_axml_decode(const ut8 *data, const ut64 data_size, PJ *pj) {
	R_RETURN_VAL_IF_FAIL (data, NULL);
	if (data_size < sizeof (chunk_header_t)) {
		return NULL;
	}
	const string_pool_t *pool = NULL;
	const namespace_t *namespace = NULL;
	const ut8 *resource_map = NULL;
	ut32 resource_map_length = 0;
	st32 depth = 0;
	RStrBuf *sb = r_strbuf_new ("");

	const chunk_header_t *header = (const chunk_header_t *)data;
	ut32 binary_size = r_read_le32 (&header->size);
	ut32 offset = r_read_le16 (&header->header_size);
	if (r_read_le16 (&header->type) != TYPE_XML || offset < sizeof (*header)
		|| offset > binary_size || binary_size > data_size) {
		goto bad;
	}
	while (offset < binary_size) {
		if (binary_size - offset < sizeof (*header)) {
			goto bad;
		}
		header = (const chunk_header_t *)(data + offset);
		ut32 chunk_size = r_read_le32 (&header->size);
		ut16 header_size = r_read_le16 (&header->header_size);
		ut16 type = r_read_le16 (&header->type);
		if (header_size < sizeof (*header) || header_size > chunk_size || chunk_size > binary_size - offset) {
			goto bad;
		}
		const ut8 *payload = data + offset + header_size;
		ut32 payload_size = chunk_size - header_size;
		if (type >= TYPE_START_NAMESPACE && type <= TYPE_END_ELEMENT && header_size < sizeof (*header) + 2 * sizeof (ut32)) {
			goto bad;
		}
		switch (type) {
		case TYPE_STRING_POOL:
			{
				if (pool || header_size < sizeof (*pool)) {
					goto bad;
				}
				pool = (const string_pool_t *)header;
				ut32 strings_offset = r_read_le32 (&pool->strings_offset);
				ut32 styles_offset = r_read_le32 (&pool->styles_offset);
				ut64 count = (ut64)r_read_le32 (&pool->string_count) + r_read_le32 (&pool->style_count);
				if (strings_offset < header_size || strings_offset > chunk_size
					|| count > (strings_offset - header_size) / sizeof (ut32)
					|| (styles_offset && (styles_offset < strings_offset || styles_offset > chunk_size))) {
					goto bad;
				}
			}
			break;
		case TYPE_START_ELEMENT:
			if (!pool || !dump_element (pj, sb, pool, namespace, payload, payload_size,
				resource_map, resource_map_length, depth, true)) {
				goto bad;
			}
			if (pj) {
				pj_ka (pj, "child");
			}
			depth++;
			break;
		case TYPE_END_ELEMENT:
			if (!pool || depth <= 0 || !dump_element (pj, sb, pool, namespace, payload, payload_size,
				resource_map, resource_map_length, --depth, false)) {
				goto bad;
			}
			if (pj) {
				pj_end (pj);
			}
			break;
		case TYPE_START_NAMESPACE:
		case TYPE_END_NAMESPACE:
			if (payload_size < sizeof (*namespace)) {
				goto bad;
			}
			if (type == TYPE_START_NAMESPACE) {
				namespace = (const namespace_t *)payload;
			}
			break;
		case TYPE_RESOURCE_MAP:
			if (payload_size % sizeof (ut32)) {
				goto bad;
			}
			resource_map = payload;
			resource_map_length = payload_size / sizeof (ut32);
			break;
		default:
			R_LOG_WARN ("Type is not recognized: %#x", type);
		}
		offset += chunk_size;
	}
	if (depth) {
		goto bad;
	}
	if (pj) {
		pj_end (pj);
	}
	return r_strbuf_drain (sb);
bad:
	R_LOG_ERROR ("Invalid Android Binary XML");
	r_strbuf_free (sb);
	return NULL;
}
