/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_types.h>
#include <r_util.h>
#include "dex.h"

char* r_bin_dex_get_version(struct r_bin_dex_obj_t* bin) {
	if (bin) {
		char *version = malloc (8);
		memset (version, 0, 8);
		memcpy (version, bin->b->buf + 4, 3);
		return version;
	}
	return NULL;
}

#define FAIL(x) { eprintf(x"\n"); goto fail; }
struct r_bin_dex_obj_t* r_bin_dex_new_buf(RBuffer *buf) {
	struct r_bin_dex_obj_t *bin = R_NEW0 (struct r_bin_dex_obj_t);
	if (!bin) {
		goto fail;
	}
	bin->size = buf->length;
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)) {
		goto fail;
	}
	// XXX: this is not endian safe
	// XXX: no need to dup all data!! just pointers to the bin->b
	// XXX: return value not checked
	/* header */
	//r_buf_read_at (bin->b, 0, (ut8*)&bin->header, sizeof (struct dex_header_t));
	if (bin->size < sizeof(struct dex_header_t))
		goto fail;
	bin->header = (*(struct dex_header_t*)bin->b->buf);

	/* strings */
//eprintf ("strings size: %d\n", bin->header.strings_size);
	#define STRINGS_SIZE ((bin->header.strings_size+1)*sizeof(ut32))
	bin->strings = (ut32 *) calloc (bin->header.strings_size + 1, sizeof (ut32));
	if (!bin->strings) {
		goto fail;
	}
	if (bin->header.strings_size > bin->size) {
		free (bin->strings);
		goto fail;
	}
	r_buf_read_at (bin->b, bin->header.strings_offset, (ut8*)bin->strings, bin->header.strings_size * sizeof (ut32));
	/* classes */
	int classes_size = bin->header.class_size * sizeof (struct dex_class_t);
	if (bin->header.class_offset + classes_size >= bin->size) {
		classes_size = bin->size - bin->header.class_offset;
	}
	if (classes_size<0) {
		classes_size = 0;
	}
	bin->header.class_size = classes_size / sizeof (struct dex_class_t);
	bin->classes = (struct dex_class_t *) malloc (classes_size);
	r_buf_read_at (bin->b, bin->header.class_offset, (ut8*)bin->classes, classes_size);
//{ ut8 *b = (ut8*)&bin->methods; eprintf ("CLASS %02x %02x %02x %02x\n", b[0], b[1], b[2], b[3]); }


	/* methods */
	int methods_size = bin->header.method_size * sizeof (struct dex_method_t);
	if (bin->header.method_offset + methods_size >= bin->size) {
		methods_size = bin->size - bin->header.method_offset;
	}
	if (methods_size < 0) {
		methods_size = 0;
	}
	bin->header.method_size = methods_size / sizeof (struct dex_method_t);
	bin->methods = (struct dex_method_t *) calloc (methods_size, 1);
	r_buf_read_at (bin->b, bin->header.method_offset, (ut8*)bin->methods, methods_size);


	/* types */
	int types_size = bin->header.types_size * sizeof (struct dex_type_t);
	if (bin->header.types_offset + types_size >= bin->size) {
		types_size = bin->size - bin->header.types_offset;
	}
	if (types_size < 0) {
		types_size = 0;
	}
	bin->header.types_size = types_size / sizeof (struct dex_type_t);
	bin->types = (struct dex_type_t *) calloc (types_size, 1);
	r_buf_read_at (bin->b, bin->header.types_offset, (ut8*)bin->types, types_size);

	/* fields */
	int fields_size = bin->header.fields_size * sizeof (struct dex_type_t);
	if (bin->header.fields_offset + fields_size >= bin->size) {
		fields_size = bin->size - bin->header.fields_offset;
	}
	if (fields_size<0) {
		fields_size = 0;
	}
	bin->header.fields_size = fields_size / sizeof (struct dex_field_t);
	bin->fields = (struct dex_field_t *) calloc (fields_size, 1);
	r_buf_read_at (bin->b, bin->header.fields_offset, (ut8*)bin->fields, fields_size);
	return bin;
fail:
	if (bin) {
		r_buf_free (bin->b);
		free (bin);
	}
	return NULL;
}

// Move to r_util ??
int dex_read_uleb128 (const ut8 *ptr) {
	int cur, result = *(ptr++);

	if (result > 0x7f) {
		cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	return result;
}

#define LEB_MAX_SIZE 6
int dex_uleb128_len (const ut8 *ptr) {
	int i = 1, result = *(ptr++);
	while (result > 0x7f && i <= LEB_MAX_SIZE) {
		result = *(ptr++);
		i++;
	}
	return i;
}

#define SIG_EXTEND(X,Y) X = (X << Y) >> Y
int dex_read_sleb128 (const char *ptr) {
	int cur, result = *(ptr++);

	if (result <= 0x7f) {
		SIG_EXTEND (result, 25);
	} else {
		cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur <= 0x7f) {
			SIG_EXTEND (result, 18);
		} else {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur <= 0x7f) {
				SIG_EXTEND (result, 11);
			} else {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur <= 0x7f) {
					SIG_EXTEND (result, 4);
				} else {
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	return result;
}
