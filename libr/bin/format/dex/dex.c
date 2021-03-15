/* radare - LGPL - Copyright 2009-2020 - pancake, h4ng3r */

#include <r_types.h>
#include <r_util.h>
#include "dex.h"

#define bprintf if (dex->verbose) eprintf

char* r_bin_dex_get_version(RBinDexObj *bin) {
	r_return_val_if_fail (bin, NULL);
	char* version = calloc (1, 8);
	if (version) {
		r_buf_read_at (bin->b, 4, (ut8*)version, 3);
		return version;
	}
	return NULL;
}

static char *getstr(RBinDexObj *bin, int idx) {
	ut8 buf[6];
	ut64 len;
	int uleblen;
	// null terminate the buf wtf
	if (!bin || idx < 0 || idx >= bin->header.strings_size || !bin->strings) {
		return NULL;
	}
	if (bin->strings[idx] >= bin->size) {
		return NULL;
	}
	if (r_buf_read_at (bin->b, bin->strings[idx], buf, sizeof (buf)) < 1) {
		return NULL;
	}
	r_buf_write_at (bin->b, r_buf_size (bin->b) - 1, (ut8 *)"\x00", 1);
	uleblen = r_uleb128 (buf, sizeof (buf), &len, NULL) - buf;
	if (!uleblen || uleblen >= bin->size) {
		return NULL;
	}
	if (!len || len >= bin->size) {
		return NULL;
	}
	if (bin->strings[idx] + uleblen >= bin->strings[idx] + bin->header.strings_size) {
		return NULL;
	}
	ut8 *ptr = R_NEWS (ut8, len + 1);
	if (ptr) {
		r_buf_read_at (bin->b, bin->strings[idx] + uleblen, ptr, len + 1);
		ptr[len] = 0;
		if (len != r_utf8_strlen (ptr)) {
			// eprintf ("WARNING: Invalid string for index %d\n", idx);
			return NULL;
		}
	}
	return (char *)ptr;
}


static const char *className(RBinDexObj *dex, int idx) {
	if (idx < 0 || idx >= dex->header.types_size) {
		return NULL;
	}
	DexType dt = dex->types[idx];
	return getstr (dex, dt.descriptor_id);
}

#if 0
static const char *dex_type_descriptor(RBinDexObj *dex, int type_idx) {
	if (type_idx < 0 || type_idx >= dex->header.types_size) {
		return NULL;
	}
	return getstr (dex, dex->types[type_idx].descriptor_id);
}

static ut64 parseNumber(RBinDexObj *dex) {
	return 0LL;
}
#endif

static void parseValue(RBinDexObj *dex) {
	ut8 argAndType = r_buf_read8 (dex->b);
	int type = (argAndType & 0x1f);
	int arg = (argAndType & 0xe0) >> 5;
	int size = arg + 1;

	bprintf ("  value size = %d\n", size);
	const char *typeName = className (dex, type);
	if (typeName) {
		bprintf ("      value value = %d (%s)\n", type, typeName);
	} else {
		bprintf ("      value value = %d\n", type);
	}
	bprintf ("      value type = %d (%s)\n", arg, className (dex, arg));
	bprintf ("      value ");
	switch (type) {
	case R_DEX_ENCVAL_BYTE:
		bprintf ("BYTE 0x%02x\n", r_buf_read8 (dex->b));
		break;
	case R_DEX_ENCVAL_SHORT:
		bprintf ("SHORT 0x%04x\n", r_buf_read_le16 (dex->b));
		break;
	case R_DEX_ENCVAL_CHAR:
		bprintf ("CHAR '%d'\n", r_buf_read8 (dex->b));
		break;
	case R_DEX_ENCVAL_INT:
		bprintf ("INT 0x%08x\n", r_buf_read_le32 (dex->b));
		break;
	case R_DEX_ENCVAL_LONG:
		bprintf ("LONG\n");
		break;
	case R_DEX_ENCVAL_FLOAT:
		bprintf ("FLOAT\n");
		break;
	case R_DEX_ENCVAL_DOUBLE:
		bprintf ("DOUBLE\n");
		break;
	case R_DEX_ENCVAL_STRING:
		{
			ut64 addr;
			r_buf_uleb128 (dex->b, &addr);
			bprintf ("STRINV ADDR 0x%"PFMT64x"\n", addr);
		}
		bprintf ("STRING\n");
		break;
	case R_DEX_ENCVAL_TYPE:
		bprintf ("TYPE\n");
		break;
	case R_DEX_ENCVAL_FIELD:
		bprintf ("FIELD\n");
		break;
	case R_DEX_ENCVAL_ENUM:
		bprintf ("ENUM\n");
		break;
	case R_DEX_ENCVAL_METHOD:
		bprintf ("METHOD\n");
		break;
	case R_DEX_ENCVAL_ARRAY:
		bprintf ("ARRAY\n");
		break;
	case R_DEX_ENCVAL_ANNOTATION:
		bprintf ("ANNOTATION\n");
		break;
	case R_DEX_ENCVAL_NULL:
		bprintf ("NULL\n");
		break;
	case R_DEX_ENCVAL_BOOLEAN:
		bprintf ("BOOLEAN\n");
		break;
	default:
		bprintf ("Unknown encoded value 0x%02x\n", type);
		break;
	}
}

static void readAnnotation(RBinDexObj *dex, bool readVisibility) {
	ut64 stringIndex, i;
	RBuffer *buf = dex->b;
	if (readVisibility) {
		bprintf ("    Visibility: ");
		ut8 b = r_buf_read8 (buf);
		switch (b) {
		case R_DEX_VISIBILITY_BUILD:
			bprintf ("BUILD\n");
			break;
		case R_DEX_VISIBILITY_RUNTIME:
			bprintf ("RUNTIME\n");
			break;
		case R_DEX_VISIBILITY_SYSTEM:
			bprintf ("SYSTEM\n");
			break;
		default:
			bprintf ("UNKNOWN (0x%02x)\n", b);
			break;
		}
	}
	st64 typeIndex = ST64_MAX;
	st64 typeSize = ST64_MAX;
	r_buf_sleb128 (buf, &typeIndex);
	r_buf_sleb128 (buf, &typeSize);
	if (typeIndex < 0 || typeIndex > 10000) {
		return;
	}
	if (typeSize < 0 || typeSize > 10000) {
		return;
	}
	const char *typeString = className (dex, typeIndex);
	if (typeString) {
		bprintf ("      TypeSize: %d %d (%s)\n", (int)typeIndex, (int)typeSize, typeString);
		for (i = 0; i < typeSize; i++) {
			r_buf_uleb128 (buf, &stringIndex);
			ut64 at = r_buf_seek (dex->b, 0, R_BUF_CUR);
			const char *name = className (dex, stringIndex);
			if (!name) {
				break;
			}
			bprintf ("      Item %d %s\n", (int)stringIndex, name);
			r_buf_seek (dex->b, at, R_BUF_SET);
			parseValue (dex);
		}
	} else {
		bprintf ("      TypeSize: %d %d (?)\n", (int)typeIndex, (int)typeSize);
	}
}

static void readAnnotationSet(RBinDexObj *dex, ut64 addr) {
	r_buf_seek (dex->b, addr, R_BUF_SET);
	ut32 i, size = r_buf_read_le32 (dex->b);
	addr += sizeof (ut32);
	if (size == UT32_MAX) {
		return;
	}
	bprintf ("            set-size: %d\n", size);
	for (i = 0; i < size; i++) {
		r_buf_seek (dex->b, addr + (i * sizeof (ut32)), R_BUF_SET);
		ut32 at = r_buf_read_le32 (dex->b);
		if (at == UT32_MAX || r_buf_seek (dex->b, at, R_BUF_SET) < 1) {
			break;
		}
		readAnnotation (dex, true);
	}
	r_buf_seek (dex->b, addr + (i * sizeof (ut32)), R_BUF_SET);
}

static void r_bin_dex_obj_free(RBinDexObj *dex) {
	if (dex) {
		r_buf_free (dex->b);
		free (dex);
	}
}

void r_bin_dex_free(RBinDexObj *dex) {
	struct dex_header_t *dexhdr = &dex->header;
	if (dex->cal_strings) {
		size_t i;
		for (i = 0; i < dexhdr->strings_size; i++) {
			free (dex->cal_strings[i]);
		}
	}
	free (dex->cal_strings);
}

RBinDexObj *r_bin_dex_new_buf(RBuffer *buf, bool verbose) {
	r_return_val_if_fail (buf, NULL);
	int i;
	RBinDexObj *dex = R_NEW0 (RBinDexObj);
	if (!dex) {
		goto fail;
	}
	dex->size = r_buf_size (buf);
	dex->b = r_buf_ref (buf);
	dex->verbose = verbose;
	/* header */
	if (dex->size < sizeof (struct dex_header_t)) {
		goto fail;
	}
	struct dex_header_t *dexhdr = &dex->header;

	if (dex->size < 112) {
		goto fail;
	}

	r_buf_seek (dex->b, 0, R_BUF_SET);
	r_buf_read (dex->b, (ut8 *)&dexhdr->magic, 8);
	dexhdr->checksum = r_buf_read_le32 (dex->b);
	r_buf_read (dex->b, (ut8 *)&dexhdr->signature, 20);
	dexhdr->size = r_buf_read_le32 (dex->b);
	dexhdr->header_size = r_buf_read_le32 (dex->b);
	dexhdr->endian = r_buf_read_le32 (dex->b);
	// TODO: this offsets and size will be used for checking,
	// so they should be checked. Check overlap, < 0, > bin.size
	dexhdr->linksection_size = r_buf_read_le32 (dex->b);
	dexhdr->linksection_offset = r_buf_read_le32 (dex->b);
	dexhdr->map_offset = r_buf_read_le32 (dex->b);
	dexhdr->strings_size = r_buf_read_le32 (dex->b);
	dexhdr->strings_offset = r_buf_read_le32 (dex->b);
	dexhdr->types_size = r_buf_read_le32 (dex->b);
	dexhdr->types_offset = r_buf_read_le32 (dex->b);
	dexhdr->prototypes_size = r_buf_read_le32 (dex->b);
	dexhdr->prototypes_offset = r_buf_read_le32 (dex->b);
	dexhdr->fields_size = r_buf_read_le32 (dex->b);
	dexhdr->fields_offset = r_buf_read_le32 (dex->b);
	dexhdr->method_size = r_buf_read_le32 (dex->b);
	dexhdr->method_offset = r_buf_read_le32 (dex->b);
	dexhdr->class_size = r_buf_read_le32 (dex->b);
	dexhdr->class_offset = r_buf_read_le32 (dex->b);
	dexhdr->data_size = r_buf_read_le32 (dex->b);
	dexhdr->data_offset = r_buf_read_le32 (dex->b);

	/* strings */
	#define STRINGS_SIZE ((dexhdr->strings_size + 1) * sizeof (ut32))
	if (dexhdr->strings_size > dex->size) {
		goto fail;
	}
	dex->strings = (ut32 *) calloc (dexhdr->strings_size + 1, sizeof (ut32));
	if (!dex->strings) {
		goto fail;
	}
	r_buf_read_at (dex->b, dexhdr->strings_offset, (ut8*)dex->strings, dexhdr->strings_size * sizeof (ut32));
	// TODO: this is unnecessary on Big endian machines
	for (i = 0; i < dexhdr->strings_size; i++) {
		ut64 offset = dexhdr->strings_offset + i * sizeof (ut32);
		if (offset + 4 > dex->size) {
			free (dex->strings);
			goto fail;
		}
		dex->strings[i] = r_read_le32 (&dex->strings[i]);
	}
	/* classes */
	// TODO: not sure about if that is needed
	size_t classes_size = dexhdr->class_size * DEX_CLASS_SIZE;
	if (dexhdr->class_offset + classes_size >= dex->size) {
		if (dexhdr->class_offset < dex->size) {
			classes_size = dex->size - dexhdr->class_offset;
		} else {
			classes_size = 0;
		}
	}
	dexhdr->class_size = classes_size / DEX_CLASS_SIZE;
	dex->classes = (struct dex_class_t *) calloc (dexhdr->class_size + 1,
		sizeof (struct dex_class_t));
	for (i = 0; i < dexhdr->class_size; i++) {
		ut64 offset = dexhdr->class_offset + i * DEX_CLASS_SIZE;
		if (offset + 32 > dex->size) {
			free (dex->strings);
			free (dex->classes);
			goto fail;
		}
		r_buf_seek (dex->b, offset, R_BUF_SET);
		dex->classes[i].class_id = r_buf_read_le32 (dex->b);
		dex->classes[i].access_flags = r_buf_read_le32 (dex->b);
		dex->classes[i].super_class = r_buf_read_le32 (dex->b);
		dex->classes[i].interfaces_offset = r_buf_read_le32 (dex->b);
		dex->classes[i].source_file = r_buf_read_le32 (dex->b);
		dex->classes[i].anotations_offset = r_buf_read_le32 (dex->b);
		dex->classes[i].class_data_offset = r_buf_read_le32 (dex->b);
		dex->classes[i].static_values_offset = r_buf_read_le32 (dex->b);
	}

	/* methods */
	size_t methods_size = dexhdr->method_size * sizeof (struct dex_method_t);
	if (dexhdr->method_offset + methods_size >= dex->size) {
		if (dexhdr->method_offset < dex->size) {
			methods_size = dex->size - dexhdr->method_offset;
		} else {
			methods_size = 0;
		}
	}
	dexhdr->method_size = methods_size / sizeof (struct dex_method_t);
	dex->methods = (struct dex_method_t *) calloc (methods_size + 1, sizeof (struct dex_method_t));
	for (i = 0; i < dexhdr->method_size; i++) {
		ut64 offset = dexhdr->method_offset + i * sizeof (struct dex_method_t);
		if (offset + 8 > dex->size) {
			free (dex->strings);
			free (dex->classes);
			free (dex->methods);
			goto fail;
		}
		r_buf_seek (dex->b, offset, R_BUF_SET);
		dex->methods[i].class_id = r_buf_read_le16 (dex->b);
		dex->methods[i].proto_id = r_buf_read_le16 (dex->b);
		dex->methods[i].name_id = r_buf_read_le32 (dex->b);
	}

	/* types */
	size_t types_size = dexhdr->types_size * sizeof (struct dex_type_t);
	if (dexhdr->types_offset + types_size >= dex->size) {
		types_size = dex->size - dexhdr->types_offset;
	}
	dexhdr->types_size = types_size / sizeof (struct dex_type_t);
	dex->types = (struct dex_type_t *) calloc (types_size + 1, sizeof (struct dex_type_t));
	for (i = 0; i < dexhdr->types_size; i++) {
		ut64 offset = dexhdr->types_offset + i * sizeof (struct dex_type_t);
		if (offset + 4 > dex->size) {
			free (dex->strings);
			free (dex->classes);
			free (dex->methods);
			free (dex->types);
			goto fail;
		}
		dex->types[i].descriptor_id = r_buf_read_le32_at (dex->b, offset);
	}

	/* fields */
	size_t fields_size = dexhdr->fields_size * sizeof (struct dex_field_t);
	if (dexhdr->fields_offset + fields_size >= dex->size) {
		if (dex->size > dexhdr->fields_offset) {
			fields_size = dex->size - dexhdr->fields_offset;
		} else {
			fields_size = 0;
		}
	}
	dexhdr->fields_size = fields_size / sizeof (struct dex_field_t);
	dex->fields = (struct dex_field_t *) calloc (fields_size + 1, sizeof (struct dex_field_t));
	for (i = 0; i < dexhdr->fields_size; i++) {
		ut64 offset = dexhdr->fields_offset + i * sizeof (struct dex_field_t);
		if (offset + 8 > dex->size) {
			free (dex->strings);
			free (dex->classes);
			free (dex->methods);
			free (dex->types);
			free (dex->fields);
			goto fail;
		}
		r_buf_seek (dex->b, offset, R_BUF_SET);
		dex->fields[i].class_id = r_buf_read_le16 (dex->b);
		dex->fields[i].type_id = r_buf_read_le16 (dex->b);
		dex->fields[i].name_id = r_buf_read_le32 (dex->b);
	}

	/* proto */
	size_t protos_size = dexhdr->prototypes_size * sizeof (struct dex_proto_t);
	if (dexhdr->prototypes_offset + protos_size >= dex->size) {
		if (dex->size > dexhdr->prototypes_offset) {
			protos_size = dex->size - dexhdr->prototypes_offset;
		} else {
			protos_size = 0;
		}
	}
	dexhdr->prototypes_size = protos_size / sizeof (struct dex_proto_t);
	dex->protos = (struct dex_proto_t *) calloc (protos_size + 1, sizeof (struct dex_proto_t));
	for (i = 0; i < dexhdr->prototypes_size; i++) {
		ut64 offset = dexhdr->prototypes_offset + i * sizeof (struct dex_proto_t);
		if (offset + 12 > dex->size) {
			free (dex->strings);
			free (dex->classes);
			free (dex->methods);
			free (dex->types);
			free (dex->fields);
			free (dex->protos);
			goto fail;
		}
		r_buf_seek (dex->b, offset, R_BUF_SET);
		dex->protos[i].shorty_id = r_buf_read_le32 (dex->b);
		dex->protos[i].return_type_id = r_buf_read_le32 (dex->b);
		dex->protos[i].parameters_off = r_buf_read_le32 (dex->b);
	}
	bprintf ("Parse annotations\n");
	for (i = 0; i < dexhdr->class_size; i++) {
		ut64 at = dex->classes[i].anotations_offset;
		if (!at || at == UT64_MAX) {
			continue;
		}
		int j;
		const char *cn = className (dex, dex->classes[i].class_id);
		r_buf_seek (dex->b, at, R_BUF_SET);
		ut32 classAnnotationsOffset = r_buf_read_le32 (dex->b);
		ut32 fieldsCount = r_buf_read_le32 (dex->b);
		ut32 annotatedMethodsCount = r_buf_read_le32 (dex->b);
		ut32 annotatedParametersCount = r_buf_read_le32 (dex->b);

		if (!fieldsCount && !annotatedMethodsCount && !annotatedParametersCount && !classAnnotationsOffset) {
			continue;
		}

		bprintf ("0x%08"PFMT64x"  annotationOffset\n", at);
		bprintf ("0x%08"PFMT64x"  classAnnotationOffset\n", (ut64)classAnnotationsOffset);
		bprintf ("            className %s\n", cn);
		bprintf ("            fieldsCount %d\n", fieldsCount);
		bprintf ("            annotatedMethodCount  %d\n", annotatedMethodsCount);
		bprintf ("            annotatedParametersCount  %d\n", annotatedParametersCount);

		if (fieldsCount == UT32_MAX || annotatedMethodsCount == UT32_MAX || annotatedParametersCount == UT32_MAX || classAnnotationsOffset == UT32_MAX) {
			continue;
		}
		if (classAnnotationsOffset > 0) {
			ut64 cur = r_buf_seek (dex->b, 0, R_BUF_CUR);
			readAnnotationSet (dex, classAnnotationsOffset);
			r_buf_seek (dex->b, cur, R_BUF_SET);
		}
		for (j = 0; j < fieldsCount; j++) {
			ut32 fieldId = r_buf_read_le32 (dex->b);
			if (fieldId == UT32_MAX) {
				break;
			}
			ut32 annotationsOffset = r_buf_read_le32 (dex->b);
			ut64 cur = r_buf_seek (dex->b, 0, R_BUF_CUR);
			bprintf ("        Annotations for fieldId %d:\n", fieldId);
			readAnnotationSet (dex, annotationsOffset);
			r_buf_seek (dex->b, cur, R_BUF_SET);
		}
		for (j = 0; j < annotatedMethodsCount ; j++) {
			ut32 methodId = r_buf_read_le32 (dex->b);
			ut32 annotationsOffset = r_buf_read_le32 (dex->b);
			if (methodId == UT32_MAX) {
				break;
			}
			ut64 cur = r_buf_seek (dex->b, 0, R_BUF_CUR);
			bprintf ("        Annotations for methodId %d:\n", methodId);
			readAnnotationSet (dex, annotationsOffset);
			r_buf_seek (dex->b, cur, R_BUF_SET);
		}
#if 0
		for (j = 0; j < annotatedParametersCount ; j++) {
			ut32 methodId = r_buf_read_le32 (dex->b);
			ut32 annotationsOffset = r_buf_read_le32 (dex->b);
			ut32 size = r_buf_read_le32 (dex->b);
			if (size == UT32_MAX || methodId == UT32_MAX || annotationsOffset == UT32_MAX) {
				break;
			}
			int k;
			for (k = 0; k < size ; k++) {
				ut32 paramIndex = r_buf_read_le32 (dex->b);
				if (paramIndex == UT32_MAX) {
					break;
				}
				ut64 cur = r_buf_seek (dex->b, 0, R_BUF_CUR);
				eprintf ("        Annotations for methodId %d + paramIndex: %d\n", methodId, paramIndex);
				eprintf ("        %s + %s\n", getstr(dex,methodId), getstr(dex,paramIndex));
				readAnnotationSet (dex, annotationsOffset);
				r_buf_seek (dex->b, cur, R_BUF_SET);
			}
		}
#endif
	}

	return dex;
fail:
	r_bin_dex_obj_free (dex);
	return NULL;
}
