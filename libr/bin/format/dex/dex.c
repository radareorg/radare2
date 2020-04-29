/* radare - LGPL - Copyright 2009-2020 - pancake, h4ng3r */

#include <r_types.h>
#include <r_util.h>
#include "dex.h"

char* r_bin_dex_get_version(RBinDexObj *bin) {
	r_return_val_if_fail (bin, NULL);
	char* version = calloc (1, 8);
	if (version) {
		r_buf_read_at (bin->b, 4, (ut8*)version, 3);
		return version;
	}
	return NULL;
}

// XXX this is never called
void r_bin_dex_free(RBinDexObj *dex) {
	size_t i;
	struct dex_header_t *dexhdr = &dex->header;
	for (i = 0; i < dexhdr->strings_size; i++) {
		free (dex->cal_strings[i]);
	}
	free (dex->cal_strings);
	free (dex);
}

RBinDexObj *r_bin_dex_new_buf(RBuffer *buf) {
	r_return_val_if_fail (buf, NULL);
	RBinDexObj *bin = R_NEW0 (RBinDexObj);
	int i;
	struct dex_header_t *dexhdr;
	if (!bin) {
		goto fail;
	}
	bin->size = r_buf_size (buf);
	bin->b = r_buf_ref (buf);
	/* header */
	if (bin->size < sizeof (struct dex_header_t)) {
		goto fail;
	}
	dexhdr = &bin->header;

	if (bin->size < 112) {
		goto fail;
	}

	r_buf_seek (bin->b, 0, R_BUF_SET);
	r_buf_read (bin->b, (ut8 *)&dexhdr->magic, 8);
	dexhdr->checksum = r_buf_read_le32 (bin->b);
	r_buf_read (bin->b, (ut8 *)&dexhdr->signature, 20);
	dexhdr->size = r_buf_read_le32 (bin->b);
	dexhdr->header_size = r_buf_read_le32 (bin->b);
	dexhdr->endian = r_buf_read_le32 (bin->b);
	// TODO: this offsets and size will be used for checking,
	// so they should be checked. Check overlap, < 0, > bin.size
	dexhdr->linksection_size = r_buf_read_le32 (bin->b);
	dexhdr->linksection_offset = r_buf_read_le32 (bin->b);
	dexhdr->map_offset = r_buf_read_le32 (bin->b);
	dexhdr->strings_size = r_buf_read_le32 (bin->b);
	dexhdr->strings_offset = r_buf_read_le32 (bin->b);
	dexhdr->types_size = r_buf_read_le32 (bin->b);
	dexhdr->types_offset = r_buf_read_le32 (bin->b);
	dexhdr->prototypes_size = r_buf_read_le32 (bin->b);
	dexhdr->prototypes_offset = r_buf_read_le32 (bin->b);
	dexhdr->fields_size = r_buf_read_le32 (bin->b);
	dexhdr->fields_offset = r_buf_read_le32 (bin->b);
	dexhdr->method_size = r_buf_read_le32 (bin->b);
	dexhdr->method_offset = r_buf_read_le32 (bin->b);
	dexhdr->class_size = r_buf_read_le32 (bin->b);
	dexhdr->class_offset = r_buf_read_le32 (bin->b);
	dexhdr->data_size = r_buf_read_le32 (bin->b);
	dexhdr->data_offset = r_buf_read_le32 (bin->b);

	/* strings */
	#define STRINGS_SIZE ((dexhdr->strings_size + 1) * sizeof (ut32))
	if (dexhdr->strings_size > bin->size) {
		goto fail;
	}
	bin->strings = R_NEWS0 (ut32, dexhdr->strings_size + 1);
	if (!bin->strings) {
		goto fail;
	}
	r_buf_read_at (bin->b, dexhdr->strings_offset, (ut8*)bin->strings, dexhdr->strings_size * sizeof (ut32));
	// TODO: this is unnecessary on Big endian machines
	for (i = 0; i < dexhdr->strings_size; i++) {
		ut64 offset = dexhdr->strings_offset + (i * sizeof (ut32));
		if (offset + 4 > bin->size) {
			break;
		}
		bin->strings[i] = r_read_le32 (&bin->strings[i]);
	}
	/* classes */
	// TODO: not sure about if that is needed
	size_t classes_size = dexhdr->class_size * DEX_CLASS_SIZE;
	if (dexhdr->class_offset + classes_size >= bin->size) {
		if (dexhdr->class_offset < bin->size) {
			classes_size = bin->size - dexhdr->class_offset;
		} else {
			classes_size = 0;
		}
	}

	dexhdr->class_size = classes_size / DEX_CLASS_SIZE;
	bin->classes = (struct dex_class_t *) calloc (dexhdr->class_size + 1,
		sizeof (struct dex_class_t));
	for (i = 0; i < dexhdr->class_size; i++) {
		ut64 offset = dexhdr->class_offset + i * DEX_CLASS_SIZE;
		if (offset + 32 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			goto fail;
		}
		r_buf_seek (bin->b, offset, R_BUF_SET);
		bin->classes[i].class_id = r_buf_read_le32 (bin->b);
		bin->classes[i].access_flags = r_buf_read_le32 (bin->b);
		bin->classes[i].super_class = r_buf_read_le32 (bin->b);
		bin->classes[i].interfaces_offset = r_buf_read_le32 (bin->b);
		bin->classes[i].source_file = r_buf_read_le32 (bin->b);
		bin->classes[i].anotations_offset = r_buf_read_le32 (bin->b);
		bin->classes[i].class_data_offset = r_buf_read_le32 (bin->b);
		bin->classes[i].static_values_offset = r_buf_read_le32 (bin->b);
	}

	/* methods */
	size_t methods_size = dexhdr->method_size * sizeof (struct dex_method_t);
	if (dexhdr->method_offset + methods_size >= bin->size) {
		if (dexhdr->method_offset < bin->size) {
			methods_size = bin->size - dexhdr->method_offset;
		} else {
			methods_size = 0;
		}
	}
	dexhdr->method_size = methods_size / sizeof (struct dex_method_t);
	bin->methods = (struct dex_method_t *) calloc (methods_size + 1, 1);
	for (i = 0; i < dexhdr->method_size; i++) {
		ut64 offset = dexhdr->method_offset + i * sizeof (struct dex_method_t);
		if (offset + 8 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			free (bin->methods);
			goto fail;
		}
		r_buf_seek (bin->b, offset, R_BUF_SET);
		bin->methods[i].class_id = r_buf_read_le16 (bin->b);
		bin->methods[i].proto_id = r_buf_read_le16 (bin->b);
		bin->methods[i].name_id = r_buf_read_le32 (bin->b);
	}

	/* types */
	size_t types_size = dexhdr->types_size * sizeof (struct dex_type_t);
	if (dexhdr->types_offset + types_size >= bin->size) {
		types_size = bin->size - dexhdr->types_offset;
	}
	dexhdr->types_size = types_size / sizeof (struct dex_type_t);
	bin->types = (struct dex_type_t *) calloc (types_size + 1, 1);
	for (i = 0; i < dexhdr->types_size; i++) {
		ut64 offset = dexhdr->types_offset + i * sizeof (struct dex_type_t);
		if (offset + 4 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			free (bin->methods);
			free (bin->types);
			goto fail;
		}
		bin->types[i].descriptor_id = r_buf_read_le32_at (bin->b, offset);
	}

	/* fields */
	size_t fields_size = dexhdr->fields_size * sizeof (struct dex_field_t);
	if (dexhdr->fields_offset + fields_size >= bin->size) {
		if (bin->size > dexhdr->fields_offset) {
			fields_size = bin->size - dexhdr->fields_offset;
		} else {
			fields_size = 0;
		}
	}
	dexhdr->fields_size = fields_size / sizeof (struct dex_field_t);
	bin->fields = (struct dex_field_t *) calloc (fields_size + 1, 1);
	for (i = 0; i < dexhdr->fields_size; i++) {
		ut64 offset = dexhdr->fields_offset + i * sizeof (struct dex_field_t);
		if (offset + 8 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			free (bin->methods);
			free (bin->types);
			free (bin->fields);
			goto fail;
		}
		r_buf_seek (bin->b, offset, R_BUF_SET);
		bin->fields[i].class_id = r_buf_read_le16 (bin->b);
		bin->fields[i].type_id = r_buf_read_le16 (bin->b);
		bin->fields[i].name_id = r_buf_read_le32 (bin->b);
	}

	/* proto */
	size_t protos_size = dexhdr->prototypes_size * sizeof (struct dex_proto_t);
	if (dexhdr->prototypes_offset + protos_size >= bin->size) {
		if (bin->size > dexhdr->prototypes_offset) {
			protos_size = bin->size - dexhdr->prototypes_offset;
		} else {
			protos_size = 0;
		}
	}
	dexhdr->prototypes_size = protos_size / sizeof (struct dex_proto_t);
	bin->protos = (struct dex_proto_t *) calloc (protos_size + 1, 1);
	for (i = 0; i < dexhdr->prototypes_size; i++) {
		ut64 offset = dexhdr->prototypes_offset + i * sizeof (struct dex_proto_t);
		if (offset + 12 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			free (bin->methods);
			free (bin->types);
			free (bin->fields);
			free (bin->protos);
			goto fail;
		}
		r_buf_seek (bin->b, offset, R_BUF_SET);
		bin->protos[i].shorty_id = r_buf_read_le32 (bin->b);
		bin->protos[i].return_type_id = r_buf_read_le32 (bin->b);
		bin->protos[i].parameters_off = r_buf_read_le32 (bin->b);
	}
	return bin;
fail:
	if (bin) {
		r_buf_free (bin->b);
		free (bin);
	}
	return NULL;
}
