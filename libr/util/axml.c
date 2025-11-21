/* radare2 - LGPL - Copyright 2021-2022 - keegan */

#include <r_util.h>
#include "axml_resources.h"

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
		ut32 string_count;
		ut32 style_count;
		ut32 flags;
		ut32 strings_offset;
		ut32 styles_offset;
		ut32 offsets[];
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
		ut32 line;
		ut32 comment;
		ut32 namespace;
		ut32 name;
		ut32 flags;
		ut16 attribute_count;
		ut16 unused0;
		ut16 unused1;
		ut16 unused2;
		attribute_t attributes[];
	})
start_element_t;

R_PACKED(
	typedef struct {
		ut32 line;
		ut32 comment;
		ut32 namespace;
		ut32 name;
	})
end_element_t;

R_PACKED(
	typedef struct {
		ut32 line;
		ut32 comment;
		ut32 prefix;
		ut32 uri;
	})
namespace_t;

static char *string_lookup(string_pool_t *pool, const ut8 *data, ut64 data_size, ut32 i, size_t *length) {
	if (i > r_read_le32 (&pool->string_count)) {
		return NULL;
	}

	ut32 offset = r_read_le32 (&pool->offsets[i]);
	ut8 *start = (ut8 *) ((uintptr_t)data + r_read_le32 (&pool->strings_offset) + 8 + offset);

	char *name = NULL;
	if (pool->flags & FLAG_UTF8) {
		if (start > data + data_size - sizeof (ut16)) {
			return NULL;
		}

		// Ignore UTF-16LE encoded length
		ut32 n = *start++;
		if (n & 0x80) {
			n = ((n & 0x7f) << 8) | *start++;
		}
		(void)n;

		if (start > data + data_size - sizeof (ut16)) {
			return NULL;
		}

		// UTF-8 encoded length
		n = *start++;
		if (n & 0x80) {
			n = ((n & 0x7f) << 8) | *start++;
		}

		if (n > data_size) {
			return NULL;
		}

		name = calloc (n + 1, 1);

		if (n == 0) {
			if (length) {
				*length = 0;
			}

			return name;
		}

		if (start > data + data_size - sizeof (ut32) - n - 1) {
			free (name);
			return NULL;
		}

		memcpy (name, start, n);

		if (length) {
			*length = n;
		}
	} else {
		if (start > data + data_size - sizeof (ut32)) {
			return NULL;
		}

		ut16 *start16 = (ut16 *)start;

		// If >0x7fff, stored as a big-endian ut32
		ut32 n = r_read_le16 (start16++);
		if (n & 0x8000) {
			n |= ((n & 0x7fff) << 16) | r_read_le16 (start16++);
		}

		// Size of UTF-16LE without NULL
		n *= 2;

		if (n * 2 > data_size) {
			return NULL;
		}

		name = calloc (n + 1, 2);

		if ((const ut8 *)start16 > data + data_size - sizeof (ut32) - n - 1) {
			free (name);
			return NULL;
		}

		// If UTF-16LE, decode to UTF-8 so we can print it to the screen
		if (r_str_utf16_to_utf8 ((ut8 *)name, n * 2, (const ut8 *)start16, n, true) < 0) {
			free (name);
			R_LOG_ERROR ("Failed to decode UTF16-LE");
			return NULL;
		}

		if (length) {
			*length = n;
		}
	}

	return name;
}

static char *resource_value(string_pool_t *pool, const ut8 *data, ut64 data_size,
	resource_value_t *value) {
	switch (value->type) {
	case RESOURCE_NULL:
		return strdup ("");
	case RESOURCE_REFERENCE:
		return r_str_newf ("@0x%x", value->data.d);
	case RESOURCE_STRING:
		return string_lookup (pool, data, data_size, r_read_le32 (&value->data.d), NULL);
	case RESOURCE_FLOAT:
		return r_str_newf ("%f", value->data.f);
	case RESOURCE_INT_DEC:
		return r_str_newf ("%d", value->data.d);
	case RESOURCE_INT_HEX:
		return r_str_newf ("0x%x", value->data.d);
	case RESOURCE_BOOL:
		return r_str_newf (value->data.d? "true": "false");
	default:
		R_LOG_WARN ("Resource type is not recognized: %#x", value->type);
		break;
	}
	return strdup ("null");
}

static bool dump_element(PJ *pj, RStrBuf *sb, string_pool_t *pool, namespace_t *namespace,
	const ut8 *data, ut64 data_size, void *element, size_t element_size,
	const ut32 *resource_map, ut32 resource_map_length, st32 *depth, bool start) {
	ut32 i;

	end_element_t *common = element;
	char *name = string_lookup (pool, data, data_size, r_read_le32 (&common->name), NULL);
	for (i = 0; i < *depth; i++) {
		r_strbuf_append (sb, "\t");
	}

	if (start) {
		start_element_t *e = element;
		if (pj) {
			pj_o (pj);
		}
		r_strbuf_appendf (sb, "<%s", name);
		if (pj) {
			pj_ko (pj, name);
		}
		ut16 count = r_read_le16 (&e->attribute_count);
		if (*depth == 0 && namespace) {
			char *key = string_lookup (pool, data, data_size, namespace->prefix, NULL);
			char *value = string_lookup (pool, data, data_size, namespace->uri, NULL);
			if (pj) {
				pj_ko (pj, "xmlns");
				pj_ks (pj, key, value);
				pj_end (pj);
			}
			r_strbuf_appendf (sb, " xmlns:%s=\"%s\"", key, value);
			free (key);
			free (value);
		}

		if (count * sizeof (attribute_t) > element_size) {
			r_strbuf_append (sb, " />");
			if (pj) {
				pj_end (pj);
			}
			R_LOG_ERROR ("Invalid element count");
			free (name);
			return false;
		}

		if (count != 0) {
			r_strbuf_append (sb, " ");
		}
		for (i = 0; i < count; i++) {
			attribute_t a = e->attributes[i];
			ut32 key_index = r_read_le32 (&a.name);
			char *key = string_lookup (pool, data, data_size, key_index, NULL);
			// If the key is empty, it is a cached resource name
			if (R_STR_ISEMPTY (key)) {
				R_FREE (key);
				if (resource_map && key_index < resource_map_length) {
					ut32 resource = r_read_le32 (&resource_map[key_index]);
					if (resource >= 0x1010000) {
						resource -= 0x1010000;
						if (resource < ANDROID_ATTRIBUTE_NAMES_SIZE) {
							key = strdup (ANDROID_ATTRIBUTE_NAMES[resource]);
						}
					}
				}
				if (!key) {
					key = strdup ("null");
				}
			}
			char *value = resource_value (pool, data, data_size, &a.value);
			// If there is a namespace on the value, and there is an active
			// namespace, assume it is the same
			if (r_read_le32 (&a.namespace) != -1 && namespace && namespace->prefix != -1) {
				char *ns = string_lookup (pool, data, data_size, namespace->prefix, NULL);
				r_strbuf_appendf (sb, "%s:%s=\"%s\"", ns, key, value);
				if (pj) {
					char *k = r_str_newf ("%s:%s", ns, key);
					pj_ks (pj, k, value);
					free (k);
				}
				free (ns);
			} else {
				r_strbuf_appendf (sb, "%s=\"%s\"", key, value);
				if (pj) {
					pj_ks (pj, key, value);
				}
			}
			if (i != count - 1) {
				r_strbuf_append (sb, " ");
			}
			free (value);
		}
	} else {
		r_strbuf_appendf (sb, "</%s", name);
	}

	r_strbuf_append (sb, ">\n");
	if (pj) {
		pj_end (pj);
	}
	free (name);
	return true;
}

R_API char *r_axml_decode(const ut8 *data, const ut64 data_size, PJ *pj) {
	R_RETURN_VAL_IF_FAIL (data, NULL);
	string_pool_t *pool = NULL;
	namespace_t *namespace = NULL;
	const ut32 *resource_map = NULL;
	ut32 resource_map_length = 0;
	st32 depth = 0;

	if (!data_size) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");

	RBuffer *buffer = r_buf_new_with_pointers (data, data_size, false);
	if (!buffer) {
		R_LOG_ERROR ("RBuffer allocation");
		goto error;
	}

	ut64 offset = 0;

	chunk_header_t header = { 0 };
	if (r_buf_fread_at (buffer, offset, (ut8 *)&header, "ssi", 1) != sizeof (header)) {
		goto bad;
	}

	if (header.type != TYPE_XML) {
		goto bad;
	}

	ut64 binary_size = header.size;
	if (binary_size > data_size) {
		goto bad;
	}
	offset += sizeof (header);

	while (offset < binary_size) {
		if (r_buf_fread_at (buffer, offset, (ut8 *)&header, "ssi", 1) != sizeof (header)) {
			goto bad;
		}

		ut16 type = header.type;

		// After reading the original chunk header, read the type-specific
		// header
		offset += sizeof (header);

		switch (type) {
		case TYPE_STRING_POOL:
			{
				ut16 header_size = header.size;
			if (header_size == 0 || header_size > data_size) {
					goto bad;
				}
				pool = malloc (header_size);
				if (!pool) {
					goto bad;
				}

				if (r_buf_read_at (buffer, offset, (void *)pool, header_size) != header_size) {
					goto bad;
				}
			}
			break;
		case TYPE_START_ELEMENT:
			{
				// The string pool must be the first header
				if (!pool) {
					goto bad;
				}
				ut16 header_size = header.size;
			if (header_size == 0 || header_size > data_size) {
					goto bad;
				}
				start_element_t *element = malloc (header_size);
				if (!element) {
					goto bad;
				}
				if (r_buf_read_at (buffer, offset, (void *)element, header_size) != header_size) {
					free (element);
					goto bad;
				}
				if (!dump_element (pj, sb, pool, namespace, data, data_size, element, header_size,
					resource_map, resource_map_length, &depth, true)) {
					free (element);
					goto bad;
				}
				if (pj) {
					pj_ka (pj, "child");
				}
				depth++;
				free (element);
			}
			break;
		case TYPE_END_ELEMENT:
			{
				depth--;
				if (depth < 0) {
					goto bad;
				}
				end_element_t end;
				if (r_buf_read_at (buffer, offset, (void *)&end, sizeof (end)) != sizeof (end)) {
					goto bad;
				}
				if (!dump_element (pj, sb, pool, namespace, data, data_size, &end, sizeof (end),
					resource_map, resource_map_length, &depth, false)) {
					goto bad;
				}
				if (pj) {
					pj_end (pj);
				}
			}
			break;
		case TYPE_START_NAMESPACE:
			{
				// If there is already a start namespace, override it
				free (namespace);
				namespace = malloc (sizeof (*namespace));
				if (!namespace) {
					goto bad;
				}
				if (r_buf_fread_at (buffer, offset, (ut8 *)namespace, "iiii", 1) != sizeof (*namespace)) {
					goto bad;
				}
			}
			break;
		case TYPE_END_NAMESPACE:
			break;
		case TYPE_RESOURCE_MAP:
			resource_map = (ut32 *) (data + offset);
			resource_map_length = header.size;
			if (resource_map_length > data_size - offset) {
				goto bad;
			}
			resource_map_length /= sizeof (ut32);
			break;
		default:
			R_LOG_WARN ("Type is not recognized: %#x", type);
		}
		int delta = header.size - sizeof (header);
		if (delta < 1) {
			R_LOG_WARN ("Truncated header size");
			break;
		}
		offset += delta;
	}
	if (pj) {
		pj_end (pj);
	}

	r_buf_free (buffer);
	free (pool);
	free (namespace);
	return r_strbuf_drain (sb);
bad:
	R_LOG_ERROR ("Invalid Android Binary XML");
error:
	r_buf_free (buffer);
	free (pool);
	r_strbuf_free (sb);
	return NULL;
}
