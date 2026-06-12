/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>

#define FTAB_HEADER_SIZE 0x30
#define FTAB_MAGIC_OFFSET 0x20
#define FTAB_ENTRY_COUNT_OFFSET 0x28
#define FTAB_ENTRY_OFFSET 0x30
#define FTAB_ENTRY_SIZE 16
#define FTAB_MAX_ENTRIES 4096

typedef struct ftab_entry_t {
	char tag[5];
	ut32 offset;
	ut32 size;
	ut32 zero;
} FtabEntry;

R_VEC_TYPE(RVecFtabEntry, FtabEntry);

static bool ftab_check_buffer(RBuffer *b) {
	ut8 buf[8];
	return b && r_buf_size (b) >= FTAB_HEADER_SIZE &&
		r_buf_read_at (b, FTAB_MAGIC_OFFSET, buf, sizeof (buf)) == sizeof (buf) &&
		!memcmp (buf, "rkosftab", 8);
}

static bool check(RBinFile *bf, RBuffer *b) {
	return ftab_check_buffer (b);
}

static bool parse_ftab_entries(RBuffer *b, RVecFtabEntry *entries) {
	if (!ftab_check_buffer (b)) {
		return false;
	}
	ut8 buf[FTAB_ENTRY_SIZE];
	if (r_buf_read_at (b, FTAB_ENTRY_COUNT_OFFSET, buf, 8) != 8) {
		return false;
	}
	const ut64 buf_size = r_buf_size (b);
	const ut32 n_entries = r_read_le32 (buf);
	const ut32 zero = r_read_le32 (buf + 4);
	if (!n_entries || n_entries > FTAB_MAX_ENTRIES || zero) {
		return false;
	}
	const ut64 table_size = (ut64)n_entries * FTAB_ENTRY_SIZE;
	if (table_size > buf_size - FTAB_ENTRY_OFFSET) {
		return false;
	}
	ut64 off = FTAB_ENTRY_OFFSET;
	ut32 i;
	for (i = 0; i < n_entries; i++, off += FTAB_ENTRY_SIZE) {
		if (r_buf_read_at (b, off, buf, sizeof (buf)) != sizeof (buf)) {
			return false;
		}
		FtabEntry entry = {0};
		memcpy (entry.tag, buf, 4);
		entry.offset = r_read_le32 (buf + 4);
		entry.size = r_read_le32 (buf + 8);
		entry.zero = r_read_le32 (buf + 12);
		if (entry.zero || entry.offset > buf_size || entry.size > buf_size - entry.offset) {
			return false;
		}
		RVecFtabEntry_push_back (entries, &entry);
	}
	return !RVecFtabEntry_empty (entries);
}

static RBinXtrMetadata *metadata_from_entry(const FtabEntry *entry) {
	RBinXtrMetadata *meta = R_NEW0 (RBinXtrMetadata);
	meta->libname = strdup (entry->tag);
	meta->machine = strdup ("Apple C4000");
	meta->type = "firmware";
	meta->xtr_type = "ftab";
	if (!strcmp (entry->tag, "GNS1")) {
		meta->arch = strdup ("arc");
		meta->bits = 16;
	} else {
		meta->arch = strdup ("unknown");
	}
	return meta;
}

static RBinXtrData *extract_entry(RBuffer *b, const FtabEntry *entry, ut32 n_entries) {
	if (!entry) {
		return NULL;
	}
	RBuffer *slice = r_buf_new_slice (b, entry->offset, entry->size);
	if (!slice) {
		return NULL;
	}
	RBinXtrMetadata *meta = metadata_from_entry (entry);
	RBinXtrData *data = r_bin_xtrdata_new (slice, 0, entry->size, n_entries, meta);
	data->offset = entry->offset;
	r_unref (slice);
	return data;
}

static bool is_gns1_entry(const FtabEntry *entry) {
	return entry && !strcmp (entry->tag, "GNS1");
}

static const FtabEntry *entry_at_index(RVecFtabEntry *entries, int idx) {
	if (idx < 0) {
		return NULL;
	}
	const FtabEntry *gns1 = NULL;
	FtabEntry *entry;
	R_VEC_FOREACH (entries, entry) {
		if (is_gns1_entry (entry)) {
			gns1 = entry;
			break;
		}
	}
	if (!gns1) {
		return idx < RVecFtabEntry_length (entries)? RVecFtabEntry_at (entries, idx): NULL;
	}
	if (!idx) {
		return gns1;
	}
	size_t n = 1;
	R_VEC_FOREACH (entries, entry) {
		if (is_gns1_entry (entry)) {
			continue;
		}
		if (n == (size_t)idx) {
			return entry;
		}
		n++;
	}
	return NULL;
}

static RBinXtrData *extract_from_buffer(RBin *bin, RBuffer *b, int idx) {
	RVecFtabEntry entries;
	RVecFtabEntry_init (&entries);
	RBinXtrData *ret = NULL;
	if (parse_ftab_entries (b, &entries)) {
		const FtabEntry *entry = entry_at_index (&entries, idx);
		ret = extract_entry (b, entry, RVecFtabEntry_length (&entries));
	}
	RVecFtabEntry_fini (&entries);
	return ret;
}

static RList *extractall_from_buffer(RBin *bin, RBuffer *b) {
	RVecFtabEntry entries;
	RVecFtabEntry_init (&entries);
	if (!parse_ftab_entries (b, &entries)) {
		RVecFtabEntry_fini (&entries);
		return NULL;
	}
	RList *list = r_list_newf (r_bin_xtrdata_free);
	if (!list) {
		RVecFtabEntry_fini (&entries);
		return NULL;
	}
	const ut32 n_entries = RVecFtabEntry_length (&entries);
	FtabEntry *entry;
	R_VEC_FOREACH (&entries, entry) {
		if (is_gns1_entry (entry)) {
			RBinXtrData *data = extract_entry (b, entry, n_entries);
			if (data) {
				r_list_append (list, data);
			}
			break;
		}
	}
	R_VEC_FOREACH (&entries, entry) {
		if (!is_gns1_entry (entry)) {
			RBinXtrData *data = extract_entry (b, entry, n_entries);
			if (data) {
				r_list_append (list, data);
			}
		}
	}
	RVecFtabEntry_fini (&entries);
	return list;
}

RBinXtrPlugin r_bin_xtr_plugin_xtr_ftab = {
	.meta = {
		.name = "xtr.ftab",
		.author = "pancake",
		.desc = "Apple C4000 FTAB firmware extractor",
		.license = "LGPL3",
	},
	.extract_from_buffer = &extract_from_buffer,
	.extractall_from_buffer = &extractall_from_buffer,
	.check = &check,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_xtr_ftab,
	.version = R2_VERSION
};
#endif
