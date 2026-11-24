/* radare - LGPL - Copyright 2026 - pancake */

#include <r_vec.h>

// R2R db/cmd/cmd_fs_ntfs

typedef struct {
	ut64 logical, physical, size;
} NtfsRun;
R_VEC_TYPE (RVecNtfsRun, NtfsRun);

typedef struct {
	RVecNtfsRun runs;
	ut8 *resident;
	ut64 size, initialized, record;
	ut32 value_offset, usa;
	int status;
} NtfsStream;

typedef struct {
	ut64 page;
	ut32 size;
	ut8 data[4096];
	bool known;
} NtfsBitmapCache;

typedef struct {
	ut64 id, parent, size, time;
	ut16 sequence, parent_sequence;
	ut32 flags;
	char type;
	char *name;
} NtfsName;

typedef struct {
	RFSRoot *root;
	GrubFS *grub;
	ut64 size, clusters, records, mirror;
	ut32 sector_size, cluster_size, record_size;
	NtfsStream mft, mft_bitmap, bitmap;
	NtfsBitmapCache mft_cache, bitmap_cache;
	RVecNtfsRun owners, bad;
	RList *names;
	HtUP *nodes, *children;
	bool geometry, native, dirty, catalog_ready, catalog_complete, owners_complete;
} NtfsFS;

typedef struct {
	NtfsFS *fs;
	GrubFS *grub;
	NtfsStream data;
	ut64 id, readable;
	bool deleted, recovery, planned, salvage;
} NtfsFile;

static ut64 ntfs_duplicate_limit(NtfsStream *stream);

static void ntfs_stream_fini(NtfsStream *stream) {
	RVecNtfsRun_fini (&stream->runs);
	free (stream->resident);
	memset (stream, 0, sizeof (*stream));
}

static bool ntfs_disk(NtfsFS *fs, ut64 offset, ut8 *buf, int len) {
	return len >= 0 && offset <= fs->size && (ut64)len <= fs->size - offset
		&& fs->root->iob.read_at (fs->root->iob.io, fs->root->delta + offset, buf, len) == len;
}

static NtfsRun *ntfs_run_at(RVecNtfsRun *runs, ut64 offset) {
	size_t low = 0, high = RVecNtfsRun_length (runs);
	while (low < high) {
		size_t mid = low + (high - low) / 2;
		NtfsRun *run = RVecNtfsRun_at (runs, mid);
		if (run->logical > offset) {
			high = mid;
		} else if (offset - run->logical >= run->size) {
			low = mid + 1;
		} else {
			return run;
		}
	}
	return NULL;
}

static bool ntfs_stream_read(NtfsFS *fs, NtfsStream *stream, ut64 offset, ut8 *buf, int len) {
	if (len < 0 || offset > stream->size || (ut64)len > stream->size - offset || stream->status == R_FS_WALK_UNSUPPORTED) {
		return false;
	}
	if (stream->resident) {
		memcpy (buf, stream->resident + offset, len);
		return true;
	}
	int done = 0;
	while (done < len) {
		ut64 logical = offset + done;
		NtfsRun *run = ntfs_run_at (&stream->runs, logical);
		if (!run) {
			return false;
		}
		int chunk = R_MIN ((ut64)(len - done), run->size - (logical - run->logical));
		if (run->physical == UT64_MAX || logical >= stream->initialized) {
			memset (buf + done, 0, chunk);
		} else {
			chunk = R_MIN ((ut64)chunk, stream->initialized - logical);
			if (!ntfs_disk (fs, run->physical + logical - run->logical, buf + done, chunk)) {
				return false;
			}
		}
		done += chunk;
	}
	return true;
}

static bool ntfs_fixup(NtfsFS *fs, ut8 *record) {
	ut32 size = fs->record_size;
	if (memcmp (record, "FILE", 4)) {
		return false;
	}
	ut32 usa = r_read_le16 (record + 4), count = r_read_le16 (record + 6);
	ut32 first = r_read_le16 (record + 20), used = r_read_le32 (record + 24), allocated = r_read_le32 (record + 28);
	if (usa < 42 || (usa & 1) || count != size / fs->sector_size + 1
			|| usa > fs->sector_size - 2 || count * 2 > fs->sector_size - 2 - usa
			|| first < usa + count * 2 || (first & 7) || first > used || used > allocated || allocated > size || used - first < 4) {
		return false;
	}
	ut16 signature = r_read_le16 (record + usa);
	ut32 i;
	for (i = 1; i < count; i++) {
		if (r_read_le16 (record + i * fs->sector_size - 2) != signature) {
			return false;
		}
	}
	for (i = 1; i < count; i++) {
		r_write_le16 (record + i * fs->sector_size - 2, r_read_le16 (record + usa + i * 2));
	}
	return true;
}

// Attribute offsets are checked before interpreting any resident value or run list.
static int ntfs_attribute(const ut8 *record, ut32 *offset, const ut8 **attribute) {
	ut32 used = r_read_le32 (record + 24);
	if (*offset > used || used - *offset < 4) {
		return R_FS_WALK_ERROR;
	}
	const ut8 *attr = record + *offset;
	if (r_read_le32 (attr) == UT32_MAX) {
		return R_FS_WALK_COMPLETE;
	}
	if (used - *offset < 24) {
		return R_FS_WALK_ERROR;
	}
	ut32 len = r_read_le32 (attr + 4);
	if (len < 24 || (len & 7) || len > used - *offset || attr[8] > 1) {
		return R_FS_WALK_ERROR;
	}
	ut32 header = attr[8]? 64: 24, name = r_read_le16 (attr + 10), namesize = (ut32)attr[9] * 2;
	if (len < header || (namesize && (name < header || name > len || namesize > len - name))) {
		return R_FS_WALK_ERROR;
	}
	ut32 value = r_read_le16 (attr + (attr[8]? 32: 20));
	if (value < header || value > len || (namesize && name + namesize > value)
			|| (!attr[8] && r_read_le32 (attr + 16) > len - value)) {
		return R_FS_WALK_ERROR;
	}
	*attribute = attr;
	*offset += len;
	return R_FS_WALK_STOPPED;
}

static ut64 ntfs_unsigned(const ut8 *bytes, unsigned size) {
	ut64 value = 0;
	unsigned i;
	for (i = 0; i < size; i++) {
		value |= (ut64)bytes[i] << (i * 8);
	}
	return value;
}

static int ntfs_runs(NtfsFS *fs, const ut8 *attr, RVecNtfsRun *runs) {
	ut64 vcn = r_read_le64 (attr + 16), highest = r_read_le64 (attr + 24), lcn = 0;
	ut32 offset = r_read_le16 (attr + 32), length = r_read_le32 (attr + 4);
	if (!vcn && highest == UT64_MAX && offset < length && !attr[offset]) {
		return R_FS_WALK_COMPLETE;
	}
	if (highest == UT64_MAX || vcn > highest || highest >= UT64_MAX / fs->cluster_size) {
		return R_FS_WALK_ERROR;
	}
	while (offset < length && attr[offset]) {
		unsigned count_size = attr[offset] & 15, delta_size = attr[offset++] >> 4;
		if (!count_size || count_size > 8 || delta_size > 8 || count_size + delta_size > length - offset) {
			return R_FS_WALK_ERROR;
		}
		ut64 count = ntfs_unsigned (attr + offset, count_size);
		offset += count_size;
		if (!count || count > highest + 1 - vcn) {
			return R_FS_WALK_ERROR;
		}
		ut64 physical = UT64_MAX;
		// Only a zero offset width denotes a hole; a signed zero delta still maps storage.
		if (delta_size) {
			ut64 delta = ntfs_unsigned (attr + offset, delta_size);
			bool negative = attr[offset + delta_size - 1] & 128;
			if (negative) {
				ut64 magnitude = delta_size == 8? ~delta + 1: ((ut64)1 << (delta_size * 8)) - delta;
				if (magnitude > lcn) {
					return R_FS_WALK_ERROR;
				}
				lcn -= magnitude;
			} else {
				if (delta > UT64_MAX - lcn) {
					return R_FS_WALK_ERROR;
				}
				lcn += delta;
			}
			if (lcn >= fs->clusters || count > fs->clusters - lcn) {
				return R_FS_WALK_ERROR;
			}
			physical = lcn * fs->cluster_size;
		}
		offset += delta_size;
		NtfsRun *run = RVecNtfsRun_emplace_back (runs);
		if (!run) {
			return R_FS_WALK_ERROR;
		}
		*run = (NtfsRun){ vcn * fs->cluster_size, physical, count * fs->cluster_size };
		vcn += count;
	}
	return offset < length && vcn == highest + 1? R_FS_WALK_COMPLETE: R_FS_WALK_ERROR;
}

static int ntfs_stream(NtfsFS *fs, const ut8 *record, ut64 id, ut32 type, const char *name, NtfsStream *stream) {
	ut32 offset = r_read_le16 (record + 20);
	const ut8 *attr;
	bool found = false, external = false;
	int status;
	stream->status = R_FS_WALK_UNSUPPORTED;
	while ((status = ntfs_attribute (record, &offset, &attr)) == R_FS_WALK_STOPPED) {
		if (r_read_le32 (attr) == 0x20) {
			external = true;
		}
		if (r_read_le32 (attr) != type || (name? attr[9] != strlen (name): attr[9] != 0)) {
			continue;
		}
		if (name) {
			unsigned i;
			ut32 start = r_read_le16 (attr + 10);
			for (i = 0; i < attr[9] && r_read_le16 (attr + start + i * 2) == (ut8)name[i]; i++) {
			}
			if (i != attr[9]) {
				continue;
			}
		}
		if (found) {
			external = true;
			continue;
		}
		found = true;
		stream->size = attr[8]? r_read_le64 (attr + 48): r_read_le32 (attr + 16);
		stream->initialized = attr[8]? r_read_le64 (attr + 56): stream->size;
		if (stream->initialized > stream->size || stream->size > INT64_MAX) {
			stream->status = R_FS_WALK_ERROR;
			continue;
		}
		if (r_read_le16 (attr + 12) & (1 | 0x4000)) {
			continue;
		}
		if (attr[8]) {
			if (r_read_le64 (attr + 16)) {
				external = true;
				continue;
			}
			stream->status = ntfs_runs (fs, attr, &stream->runs);
			NtfsRun *last = RVecNtfsRun_last (&stream->runs);
			if (last? stream->size > last->logical + last->size: stream->size != 0) {
				stream->status = R_FS_WALK_ERROR;
			}
		} else {
			ut32 size = r_read_le32 (attr + 16), value = r_read_le16 (attr + 20);
			stream->resident = malloc (R_MAX (size, 1));
			if (!stream->resident) {
				stream->status = R_FS_WALK_ERROR;
				continue;
			}
			memcpy (stream->resident, attr + value, size);
			stream->record = id;
			stream->value_offset = attr - record + value;
			stream->usa = r_read_le16 (record + 4);
			stream->size = stream->initialized = size;
			stream->status = R_FS_WALK_COMPLETE;
		}
	}
	if (status != R_FS_WALK_COMPLETE) {
		stream->status = R_FS_WALK_ERROR;
	} else if (external && stream->status != R_FS_WALK_ERROR) {
		stream->status = R_FS_WALK_UNSUPPORTED;
	}
	return stream->status;
}

static bool ntfs_record(NtfsFS *fs, ut64 id, ut8 *record) {
	return id < fs->records && ntfs_stream_read (fs, &fs->mft, id * fs->record_size, record, fs->record_size)
		&& ntfs_fixup (fs, record) && (r_read_le16 (record + 4) < 48
			|| !r_read_le32 (record + 44) || r_read_le32 (record + 44) == (ut32)id);
}

static int ntfs_bit(NtfsFS *fs, NtfsStream *stream, NtfsBitmapCache *cache, ut64 bit) {
	ut64 byte = bit / 8;
	if (stream->status != R_FS_WALK_COMPLETE || byte >= stream->initialized) {
		return -1;
	}
	if (!cache->size || byte < cache->page || byte - cache->page >= cache->size) {
		cache->page = byte / sizeof (cache->data) * sizeof (cache->data);
		cache->size = R_MIN ((ut64)sizeof (cache->data), stream->initialized - cache->page);
		cache->known = true;
		ut64 offset = cache->page, end = offset + cache->size;
		while (!stream->resident && offset < end) {
			NtfsRun *run = ntfs_run_at (&stream->runs, offset);
			if (!run || run->physical == UT64_MAX) {
				cache->known = false;
				break;
			}
			offset += R_MIN (end - offset, run->size - (offset - run->logical));
		}
		cache->known = cache->known && ntfs_stream_read (fs, stream, cache->page, cache->data, cache->size);
	}
	return cache->known? (cache->data[byte - cache->page] >> (bit % 8)) & 1: -1;
}

static bool ntfs_initialize(NtfsFS *fs) {
	ut8 boot[512];
	if (fs->root->delta > UT64_MAX - sizeof (boot)
			|| fs->root->iob.read_at (fs->root->iob.io, fs->root->delta, boot, sizeof (boot)) != sizeof (boot)
			|| memcmp (boot + 3, "NTFS    ", 8)) {
		return false;
	}
	fs->sector_size = r_read_le16 (boot + 11);
	ut32 spc = boot[13];
	if (fs->sector_size < 512 || fs->sector_size > 4096 || (fs->sector_size & (fs->sector_size - 1))
			|| !spc || (spc & (spc - 1))) {
		return false;
	}
	fs->cluster_size = fs->sector_size * spc;
	fs->record_size = ntfs_clusters_to_size ((st8)boot[64], fs->cluster_size);
	ut32 index_size = ntfs_clusters_to_size ((st8)boot[68], fs->cluster_size);
	ut64 mft = r_read_le64 (boot + 48);
	fs->mirror = r_read_le64 (boot + 56);
	if (!fs->record_size || fs->record_size < fs->sector_size || fs->record_size > 65536
			|| fs->record_size % fs->sector_size || index_size < fs->sector_size
			|| index_size > 65536 || index_size % fs->sector_size) {
		return false;
	}
	fs->geometry = true;
	ut64 sectors = r_read_le64 (boot + 40);
	if (!sectors || sectors > (UT64_MAX - fs->root->delta) / fs->sector_size) {
		return false;
	}
	fs->size = sectors * fs->sector_size;
	fs->clusters = sectors / spc;
	if (mft >= fs->clusters) {
		return false;
	}
	if (r_read_le16 (boot + 510) != 0xaa55) {
		R_LOG_WARN ("Damaged NTFS boot signature: retaining MFT inspection");
	}
	ut8 *record = malloc (fs->record_size);
	if (!record) {
		return false;
	}
	bool ok = ntfs_disk (fs, mft * fs->cluster_size, record, fs->record_size) && ntfs_fixup (fs, record)
		&& ntfs_stream (fs, record, 0, 0x80, NULL, &fs->mft) == R_FS_WALK_COMPLETE
		&& !fs->mft.resident && fs->mft.initialized <= fs->mft.size;
	if (ok) {
		fs->records = fs->mft.initialized / fs->record_size;
		NtfsRun *first = ntfs_run_at (&fs->mft.runs, 0);
		ok = first && first->physical == mft * fs->cluster_size && ntfs_duplicate_limit (&fs->mft) == UT64_MAX;
		size_t i;
		for (i = 0; i < RVecNtfsRun_length (&fs->mft.runs); i++) {
			if (RVecNtfsRun_at (&fs->mft.runs, i)->physical == UT64_MAX) {
				ok = false;
			}
		}
		if (!ok) {
			fs->mft.status = R_FS_WALK_ERROR;
		}
		ntfs_stream (fs, record, 0, 0xb0, NULL, &fs->mft_bitmap);
		if (ntfs_record (fs, 6, record)) {
			ntfs_stream (fs, record, 6, 0x80, NULL, &fs->bitmap);
		}
		fs->dirty = true;
		if (ntfs_record (fs, 3, record)) {
			ut32 offset = r_read_le16 (record + 20);
			const ut8 *attr;
			while (ntfs_attribute (record, &offset, &attr) == R_FS_WALK_STOPPED) {
				if (r_read_le32 (attr) == 0x70 && !attr[8] && r_read_le32 (attr + 16) >= 12) {
					const ut8 *value = attr + r_read_le16 (attr + 20);
					fs->dirty = value[8] != 3 || value[9] > 1 || (r_read_le16 (value + 10) & 1);
				}
			}
		}
	}
	free (record);
	return ok && fs->records > 6;
}

static void ntfs_name_free(void *ptr) {
	NtfsName *name = ptr;
	free (name->name);
	free (name);
}

static int ntfs_physical_compare(const NtfsRun *left, const NtfsRun *right) {
	return left->physical < right->physical? -1: left->physical > right->physical;
}

static void ntfs_merge_runs(RVecNtfsRun *runs) {
	RVecNtfsRun_sort (runs, ntfs_physical_compare);
	size_t i, count = 0, length = RVecNtfsRun_length (runs);
	for (i = 0; i < length; i++) {
		NtfsRun run = *RVecNtfsRun_at (runs, i);
		NtfsRun *previous = count? RVecNtfsRun_at (runs, count - 1): NULL;
		if (previous && run.physical <= previous->physical + previous->size) {
			previous->size = R_MAX (previous->size, run.physical + run.size - previous->physical);
		} else {
			run.logical = run.physical;
			*RVecNtfsRun_at (runs, count++) = run;
		}
	}
	while (RVecNtfsRun_length (runs) > count) {
		RVecNtfsRun_pop_back (runs);
	}
}

static bool ntfs_live_runs(NtfsFS *fs, const ut8 *record, bool bad) {
	ut32 offset = r_read_le16 (record + 20);
	const ut8 *attr;
	int status;
	bool complete = true;
	while ((status = ntfs_attribute (record, &offset, &attr)) == R_FS_WALK_STOPPED) {
		if (r_read_le32 (attr) == 0x20) {
			complete = false;
		}
		if (!attr[8]) {
			continue;
		}
		RVecNtfsRun runs = {0};
		complete &= ntfs_runs (fs, attr, &runs) == R_FS_WALK_COMPLETE;
		size_t i;
		for (i = 0; i < RVecNtfsRun_length (&runs); i++) {
			NtfsRun *run = RVecNtfsRun_at (&runs, i);
			if (run->physical == UT64_MAX) {
				continue;
			}
			NtfsRun *copy = RVecNtfsRun_emplace_back (&fs->owners);
			if (!copy) {
				RVecNtfsRun_fini (&runs);
				return false;
			}
			*copy = *run;
			if (bad && r_read_le32 (attr) == 0x80) {
				copy = RVecNtfsRun_emplace_back (&fs->bad);
				if (!copy) {
					RVecNtfsRun_fini (&runs);
					return false;
				}
				*copy = *run;
			}
		}
		RVecNtfsRun_fini (&runs);
	}
	return complete && status == R_FS_WALK_COMPLETE;
}

static void ntfs_children_free(HtUPKv *kv) {
	r_list_free (kv->value);
}

static bool ntfs_add_name(NtfsFS *fs, NtfsName *name) {
	if (!r_list_append (fs->names, name)) {
		ntfs_name_free (name);
		return false;
	}
	if (!ht_up_find (fs->nodes, name->id, NULL) && !ht_up_insert (fs->nodes, name->id, name)) {
		return false;
	}
	RList *children = ht_up_find (fs->children, name->parent, NULL);
	if (!children) {
		children = r_list_new ();
		if (!children || !ht_up_insert (fs->children, name->parent, children)) {
			r_list_free (children);
			return false;
		}
	}
	return r_list_append (children, name) != NULL;
}

static bool ntfs_valid_name(const ut8 *value, ut32 length) {
	ut32 i;
	for (i = 0; i < length; i++) {
		ut16 ch = r_read_le16 (value + i * 2);
		if (!ch || ch == '/' || ch == '\\' || (ch >= 0xdc00 && ch <= 0xdfff)) {
			return false;
		}
		if (ch >= 0xd800 && ch <= 0xdbff) {
			if (++i >= length) {
				return false;
			}
			ch = r_read_le16 (value + i * 2);
			if (ch < 0xdc00 || ch > 0xdfff) {
				return false;
			}
		}
	}
	return true;
}

static int ntfs_name_compare(const void *a, const void *b) {
	const NtfsName *left = a, *right = b;
	int result = r_str_casecmp (left->name, right->name);
	return result? result: strcmp (left->name, right->name);
}

static bool ntfs_sort_children(void *user, const ut64 id, const void *value) {
	r_list_sort ((RList *)value, ntfs_name_compare);
	return true;
}

static bool ntfs_catalog(NtfsFS *fs) {
	if (fs->catalog_ready) {
		return fs->catalog_complete;
	}
	fs->catalog_ready = true;
	fs->catalog_complete = true;
	fs->owners_complete = fs->mft_bitmap.status == R_FS_WALK_COMPLETE;
	fs->owners_complete &= fs->mft_bitmap.initialized >= (fs->records + 7) / 8;
	fs->owners_complete &= !fs->dirty;
	fs->names = r_list_newf (ntfs_name_free);
	fs->nodes = ht_up_new0 ();
	fs->children = ht_up_new (NULL, ntfs_children_free, NULL);
	ut8 *record = malloc (fs->record_size);
	if (!record || !fs->names || !fs->nodes || !fs->children) {
		free (record);
		fs->catalog_complete = fs->owners_complete = false;
		return false;
	}
	NtfsRun *boot = RVecNtfsRun_emplace_back (&fs->owners);
	if (boot) {
		*boot = (NtfsRun){ 0, 0, fs->cluster_size };
	} else {
		fs->owners_complete = false;
	}
	if (fs->mirror < fs->clusters) {
		NtfsRun *mirror = RVecNtfsRun_emplace_back (&fs->owners);
		if (mirror) {
			ut64 offset = fs->mirror * fs->cluster_size;
			*mirror = (NtfsRun){ offset, offset, R_MIN (fs->size - offset, R_MAX ((ut64)fs->record_size * 4, fs->cluster_size)) };
		} else {
			fs->owners_complete = false;
		}
	} else {
		fs->owners_complete = false;
	}
	size_t index;
	for (index = 0; index < RVecNtfsRun_length (&fs->mft.runs); index++) {
		NtfsRun *copy = RVecNtfsRun_emplace_back (&fs->owners);
		if (!copy) {
			fs->owners_complete = false;
			break;
		}
		*copy = *RVecNtfsRun_at (&fs->mft.runs, index);
	}
	ut64 id;
	for (id = 0; id < fs->records; id++) {
		int allocated = ntfs_bit (fs, &fs->mft_bitmap, &fs->mft_cache, id);
		if (!ntfs_record (fs, id, record)) {
			if (allocated != 0 || id < 12) {
				fs->catalog_complete = fs->owners_complete = false;
			}
			continue;
		}
		bool live = id < 24 || (r_read_le16 (record + 22) & 1) || allocated != 0;
		if (live) {
			fs->owners_complete &= ntfs_live_runs (fs, record, id == 8);
		}
		if (r_read_le64 (record + 32)) {
			continue;
		}
		ut32 offset = r_read_le16 (record + 20);
		const ut8 *attr;
		NtfsStream data = {0};
		ntfs_stream (fs, record, id, 0x80, NULL, &data);
		bool named = false;
		int status;
		while ((status = ntfs_attribute (record, &offset, &attr)) == R_FS_WALK_STOPPED) {
			if (r_read_le32 (attr) != 0x30 || attr[8] || r_read_le32 (attr + 16) < 66) {
				continue;
			}
			const ut8 *value = attr + r_read_le16 (attr + 20);
			ut32 length = value[64];
			if (!length || value[65] > 3 || value[65] == 2 || length * 2 > r_read_le32 (attr + 16) - 66
					|| !ntfs_valid_name (value + 66, length)) {
				continue;
			}
			char name[1024];
			int bytes = r_str_utf16_to_utf8 ((ut8 *)name, sizeof (name) - 1, value + 66, length * 2, false);
			if (bytes < 1) {
				continue;
			}
			name[bytes] = 0;
			if (strchr (name, '/') || strchr (name, '\\')) {
				continue;
			}
			NtfsName *entry = R_NEW0 (NtfsName);
			entry->id = id;
			entry->parent = r_read_le64 (value) & 0xffffffffffffULL;
			entry->parent_sequence = r_read_le64 (value) >> 48;
			entry->sequence = r_read_le16 (record + 16);
			entry->type = r_read_le16 (record + 22) & 2? 'd': r_read_le32 (value + 56) & 0x20000000? 's': 'f';
			entry->size = entry->type == 'f'? data.size: 0;
			entry->time = ntfs_filetime_to_unix (r_read_le64 (value + 16));
			entry->flags = r_read_le16 (record + 22) & 1? 0: R_FS_FILE_DELETED | R_FS_FILE_HEURISTIC;
			if ((entry->flags & R_FS_FILE_DELETED) && allocated > 0) {
				entry->flags |= R_FS_FILE_CONFLICT;
			} else if (allocated < 0) {
				entry->flags |= R_FS_FILE_PARTIAL;
			}
			entry->name = strdup (name);
			if (!entry->name) {
				ntfs_name_free (entry);
				fs->catalog_complete = fs->owners_complete = false;
				break;
			}
			if (!ntfs_add_name (fs, entry)) {
				fs->catalog_complete = fs->owners_complete = false;
				break;
			}
			named = true;
		}
		if (!named && (id == 5 || (id >= 24 && !live && r_read_le16 (record + 16) && data.status != R_FS_WALK_UNSUPPORTED))) {
			NtfsName *entry = R_NEW0 (NtfsName);
			entry->id = id;
			entry->parent = id == 5? 5: UT64_MAX;
			entry->sequence = r_read_le16 (record + 16);
			entry->parent_sequence = entry->sequence;
			entry->type = id == 5? 'd': 'f';
			entry->size = data.size;
			entry->flags = id == 5? 0: R_FS_FILE_DELETED | R_FS_FILE_HEURISTIC;
			entry->name = id == 5? strdup ("."): r_str_newf ("mft-%"PFMT64u, id);
			if (!entry->name) {
				ntfs_name_free (entry);
				fs->catalog_complete = fs->owners_complete = false;
			} else if (!ntfs_add_name (fs, entry)) {
				fs->catalog_complete = fs->owners_complete = false;
			}
		}
		fs->catalog_complete &= status == R_FS_WALK_COMPLETE;
		ntfs_stream_fini (&data);
	}
	free (record);
	ntfs_merge_runs (&fs->owners);
	ntfs_merge_runs (&fs->bad);
	ht_up_foreach (fs->children, ntfs_sort_children, NULL);
	RListIter *iter;
	NtfsName *name;
	r_list_foreach (fs->names, iter, name) {
		NtfsName *parent = ht_up_find (fs->nodes, name->parent, NULL);
		if (name->parent != UT64_MAX && (!parent || parent->sequence != name->parent_sequence || parent->type != 'd')) {
			name->flags |= R_FS_FILE_CONFLICT | R_FS_FILE_HEURISTIC;
		}
	}
	if (!fs->catalog_complete) {
		R_LOG_WARN ("Damaged NTFS metadata: retaining readable MFT entries");
	}
	return fs->catalog_complete;
}

static NtfsName *ntfs_named_record(NtfsFS *fs, ut64 id) {
	return fs->nodes? ht_up_find (fs->nodes, id, NULL): NULL;
}

static ut64 ntfs_lookup(NtfsFS *fs, const char *path) {
	ntfs_catalog (fs);
	ut64 parent = 5;
	char *copy = strdup (path), *state = NULL;
	if (!copy) {
		return UT64_MAX;
	}
	char *part = r_str_tok_r (copy, "/", &state);
	while (part) {
		NtfsName *directory = ntfs_named_record (fs, parent);
		if (!directory || directory->type != 'd') {
			parent = UT64_MAX;
			break;
		}
		if (!strcmp (part, ".") || !strcmp (part, "..")) {
			if (!strcmp (part, "..")) {
				parent = directory->parent;
			}
			part = r_str_tok_r (NULL, "/", &state);
			continue;
		}
		ut64 found = UT64_MAX;
		bool exact = false, ambiguous = false;
		RListIter *iter;
		NtfsName *name;
		RList *children = ht_up_find (fs->children, parent, NULL);
		r_list_foreach (children, iter, name) {
			if (directory && name->parent == parent && name->parent_sequence == directory->sequence
					&& !(name->flags & R_FS_FILE_DELETED) && !r_str_casecmp (name->name, part)) {
				bool matches = !strcmp (name->name, part);
				if (exact && !matches) {
					continue;
				}
				if (matches && !exact) {
					found = name->id;
					exact = true;
					ambiguous = false;
				} else {
					ambiguous |= found != UT64_MAX && found != name->id;
					found = name->id;
				}
			}
		}
		parent = ambiguous? UT64_MAX: found;
		if (parent == UT64_MAX) {
			break;
		}
		part = r_str_tok_r (NULL, "/", &state);
	}
	free (copy);
	return parent;
}

static ut64 ntfs_duplicate_limit(NtfsStream *stream) {
	RVecNtfsRun physical = {0};
	size_t i;
	ut64 limit = UT64_MAX;
	for (i = 0; i < RVecNtfsRun_length (&stream->runs); i++) {
		NtfsRun *run = RVecNtfsRun_at (&stream->runs, i);
		if (run->physical != UT64_MAX) {
			NtfsRun *copy = RVecNtfsRun_emplace_back (&physical);
			if (!copy) {
				limit = 0;
				goto done;
			}
			*copy = *run;
		}
	}
	RVecNtfsRun_sort (&physical, ntfs_physical_compare);
	ut64 end = 0, first = 0;
	for (i = 0; i < RVecNtfsRun_length (&physical); i++) {
		NtfsRun *run = RVecNtfsRun_at (&physical, i);
		if (i && run->physical < end) {
			limit = R_MIN (limit, R_MAX (first, run->logical));
			first = R_MIN (first, run->logical);
			end = R_MAX (end, run->physical + run->size);
		} else {
			first = run->logical;
			end = run->physical + run->size;
		}
	}
 done:
	RVecNtfsRun_fini (&physical);
	return limit;
}

static bool ntfs_resident_location(NtfsFS *fs, NtfsStream *stream, ut64 logical, ut64 *physical, ut64 *available) {
	ut64 offset = stream->value_offset + logical;
	ut64 sector = offset / fs->sector_size, within = offset % fs->sector_size;
	// The original sector-trailer bytes are stored in the update sequence array.
	if (within >= fs->sector_size - 2) {
		offset = stream->usa + (sector + 1) * 2 + within - (fs->sector_size - 2);
		*available = fs->sector_size - within;
	} else {
		*available = fs->sector_size - 2 - within;
	}
	ut64 address = stream->record * fs->record_size + offset;
	NtfsRun *run = ntfs_run_at (&fs->mft.runs, address);
	if (!run || run->physical == UT64_MAX) {
		return false;
	}
	*physical = run->physical + address - run->logical;
	*available = R_MIN (*available, run->size - (address - run->logical));
	return true;
}

static int ntfs_emit_range(RFSRange *run, const RFSRange *next, RFSRangeCb cb, void *user) {
	if (run->size && (run->flags != next->flags || run->logical + run->size != next->logical
			|| (next->physical != UT64_MAX && run->physical + run->size != next->physical))) {
		if (!cb (run, user)) {
			return R_FS_WALK_STOPPED;
		}
		run->size = 0;
	}
	if (!run->size) {
		*run = *next;
	} else {
		run->size += next->size;
	}
	return R_FS_WALK_COMPLETE;
}

static int FSP(_forensic_extents)(RFSFile *file, RFSRangeCb cb, void *user) {
	NtfsFile *entry = file->ptr;
	NtfsFS *fs = entry->fs;
	NtfsStream *stream = &entry->data;
	if (!fs->native || file->type != 'f' || stream->status == R_FS_WALK_UNSUPPORTED) {
		return R_FS_WALK_UNSUPPORTED;
	}
	ut64 limit = file->size, logical = 0, readable = UT64_MAX;
	int status = stream->status;
	if (entry->recovery) {
		ntfs_catalog (fs);
		int allocated = ntfs_bit (fs, &fs->mft_bitmap, &fs->mft_cache, entry->id);
		if (!entry->deleted || !fs->owners_complete || allocated != 0) {
			file->flags |= R_FS_FILE_PARTIAL;
			if (!entry->deleted || allocated > 0) {
				file->flags |= R_FS_FILE_CONFLICT;
			}
			entry->planned = true;
			entry->readable = 0;
			return R_FS_WALK_ERROR;
		}
		ut64 duplicate = ntfs_duplicate_limit (stream);
		if (duplicate < limit) {
			limit = duplicate;
			file->flags |= R_FS_FILE_CONFLICT;
			status = R_FS_WALK_ERROR;
		}
	}
	RFSRange run = {0};
	while (logical < limit) {
		ut64 physical, size;
		ut32 flags;
		if (stream->resident) {
			if (!ntfs_resident_location (fs, stream, logical, &physical, &size)) {
				status = R_FS_WALK_ERROR;
				break;
			}
			flags = R_FS_RANGE_ALLOCATED;
		} else {
			NtfsRun *mapping = ntfs_run_at (&stream->runs, logical);
			if (!mapping) {
				status = R_FS_WALK_ERROR;
				break;
			}
			size = mapping->size - (logical - mapping->logical);
			physical = mapping->physical == UT64_MAX? UT64_MAX: mapping->physical + logical - mapping->logical;
			if (physical == UT64_MAX) {
				flags = R_FS_RANGE_SPARSE;
			} else {
				size = R_MIN (size, fs->cluster_size - physical % fs->cluster_size);
				int allocated = ntfs_bit (fs, &fs->bitmap, &fs->bitmap_cache, physical / fs->cluster_size);
				if (entry->recovery && (allocated != 0 || ntfs_run_at (&fs->owners, physical))) {
					if (allocated > 0 || ntfs_run_at (&fs->owners, physical)) {
						file->flags |= R_FS_FILE_CONFLICT;
					}
					status = R_FS_WALK_ERROR;
					if (!entry->salvage) {
						break;
					}
					readable = R_MIN (readable, logical);
					logical += R_MIN (size, limit - logical);
					continue;
				}
				flags = allocated < 0? R_FS_RANGE_UNKNOWN: allocated? R_FS_RANGE_ALLOCATED: R_FS_RANGE_FREE;
				if (allocated < 0) {
					status = R_FS_WALK_ERROR;
				}
				if (logical >= stream->initialized) {
					flags |= R_FS_RANGE_UNWRITTEN;
				} else {
					size = R_MIN (size, stream->initialized - logical);
				}
			}
		}
		size = R_MIN (size, limit - logical);
		RFSRange next = { logical, physical == UT64_MAX? UT64_MAX: file->root->delta + physical, size, flags };
		if (ntfs_emit_range (&run, &next, cb, user) == R_FS_WALK_STOPPED) {
			return R_FS_WALK_STOPPED;
		}
		logical += size;
	}
	if (run.size && !cb (&run, user)) {
		return R_FS_WALK_STOPPED;
	}
	if (entry->recovery) {
		entry->readable = R_MIN (readable, logical);
		entry->planned = true;
	}
	if (status != R_FS_WALK_COMPLETE || logical != file->size) {
		file->flags |= R_FS_FILE_PARTIAL;
		return R_FS_WALK_ERROR;
	}
	return R_FS_WALK_COMPLETE;
}

static bool ntfs_accept_range(const RFSRange *range, void *user) {
	return true;
}

static void FSP(_forensic_close)(RFSFile *file) {
	NtfsFile *entry = file->ptr;
	if (entry->grub) {
		file->ptr = entry->grub;
		FSP(_close) (file);
		grubfs_free (entry->grub);
	}
	ntfs_stream_fini (&entry->data);
	free (entry);
	file->ptr = NULL;
}

static RFSFile *FSP(_forensic_open_id)(RFSRoot *root, ut64 id, ut32 flags) {
	NtfsFS *fs = root->ptr;
	if (!fs->native || (flags & ~(R_FS_OPEN_RECOVER | R_FS_OPEN_SALVAGE)) || id >= fs->records) {
		return NULL;
	}
	ut8 *record = malloc (fs->record_size);
	if (!record) {
		return NULL;
	}
	if (!ntfs_record (fs, id, record) || r_read_le64 (record + 32) || !r_read_le16 (record + 16)) {
		free (record);
		return NULL;
	}
	bool deleted = !(r_read_le16 (record + 22) & 1);
	if ((flags & R_FS_OPEN_RECOVER) && (id < 24 || !deleted || ntfs_bit (fs, &fs->mft_bitmap, &fs->mft_cache, id) != 0)) {
		free (record);
		return NULL;
	}
	char *name = r_str_newf ("mft-%"PFMT64u, id);
	RFSFile *file = r_fs_file_new (root, name);
	free (name);
	NtfsFile *entry = R_NEW0 (NtfsFile);
	entry->fs = fs;
	entry->id = id;
	entry->deleted = deleted;
	entry->recovery = flags & R_FS_OPEN_RECOVER;
	entry->salvage = entry->recovery && (flags & R_FS_OPEN_SALVAGE);
	file->ptr = entry;
	file->id = id;
	file->type = r_read_le16 (record + 22) & 2? 'd': 'f';
	ut32 offset = r_read_le16 (record + 20);
	const ut8 *attr;
	while (ntfs_attribute (record, &offset, &attr) == R_FS_WALK_STOPPED) {
		if (attr[8]) {
			continue;
		}
		const ut8 *value = attr + r_read_le16 (attr + 20);
		if (r_read_le32 (attr) == 0x10 && r_read_le32 (attr + 16) >= 16) {
			file->time = ntfs_filetime_to_unix (r_read_le64 (value + 8));
		} else if (r_read_le32 (attr) == 0x30 && r_read_le32 (attr + 16) >= 66
				&& file->type != 'd' && (r_read_le32 (value + 56) & 0x20000000)) {
			file->type = 's';
		}
	}
	ntfs_stream (fs, record, id, 0x80, NULL, &entry->data);
	file->size = entry->data.size;
	if (deleted) {
		file->flags |= R_FS_FILE_DELETED;
	}
	if (entry->data.resident && file->size) {
		ut64 physical, available;
		if (ntfs_resident_location (fs, &entry->data, 0, &physical, &available)) {
			file->off = root->delta + physical;
		}
	} else {
		NtfsRun *run = ntfs_run_at (&entry->data.runs, 0);
		if (run && run->physical != UT64_MAX) {
			file->off = root->delta + run->physical;
		}
	}
	free (record);
	return file;
}

static int FSP(_forensic_read)(RFSFile *file, ut64 addr, int len) {
	NtfsFile *entry = file->ptr;
	if (entry->grub && entry->data.status == R_FS_WALK_UNSUPPORTED) {
		file->ptr = entry->grub;
		int result = FSP(_read) (file, addr, len);
		file->ptr = entry;
		return result;
	}
	if (addr >= file->size) {
		return 0;
	}
	ut64 readable = file->size;
	if (entry->deleted) {
		if (!entry->planned) {
			bool recovery = entry->recovery;
			entry->recovery = true;
			FSP(_forensic_extents) (file, ntfs_accept_range, NULL);
			entry->recovery = recovery;
		}
		readable = entry->planned? entry->readable: 0;
	}
	if (addr >= readable) {
		return -1;
	}
	len = R_MIN ((ut64)len, readable - addr);
	int done = 0;
	while (done < len) {
		ut64 logical = addr + done;
		int chunk = len - done;
		if (!entry->data.resident) {
			NtfsRun *run = ntfs_run_at (&entry->data.runs, logical);
			if (!run) {
				file->flags |= R_FS_FILE_PARTIAL;
				break;
			}
			chunk = R_MIN ((ut64)chunk, run->size - (logical - run->logical));
			chunk = R_MIN ((ut64)chunk, entry->fs->cluster_size - logical % entry->fs->cluster_size);
		}
		if (!ntfs_stream_read (entry->fs, &entry->data, logical, file->data + done, chunk)) {
			file->flags |= R_FS_FILE_PARTIAL;
			break;
		}
		done += chunk;
	}
	return done? done: -1;
}

static RFSFile *FSP(_forensic_open)(RFSRoot *root, const char *path, bool create) {
	NtfsFS *fs = root->ptr;
	ut64 id = fs->native? ntfs_lookup (fs, path): UT64_MAX;
	RFSFile *native = id != UT64_MAX? FSP(_forensic_open_id) (root, id, 0): NULL;
	if (native && native->type == 'f' && ((NtfsFile *)native->ptr)->data.status != R_FS_WALK_UNSUPPORTED) {
		NtfsFile *entry = native->ptr;
		if (entry->data.status == R_FS_WALK_ERROR && !entry->data.resident && !RVecNtfsRun_length (&entry->data.runs)) {
			FSP(_forensic_close) (native);
			r_fs_file_free (native);
			return NULL;
		}
		RFSFile *file = r_fs_file_new (root, path);
		file->ptr = entry;
		file->id = native->id;
		file->off = native->off;
		file->size = native->size;
		file->type = native->type;
		file->flags = native->flags;
		file->time = native->time;
		r_fs_file_free (native);
		return file;
	}
	RFSFile *file = FSP(_open) (root, path, create);
	if (!file) {
		if (native) {
			FSP(_forensic_close) (native);
			r_fs_file_free (native);
		}
		return NULL;
	}
	NtfsFile *entry = native? native->ptr: R_NEW0 (NtfsFile);
	entry->fs = fs;
	entry->grub = file->ptr;
	if (!native) {
		entry->data.status = R_FS_WALK_UNSUPPORTED;
	} else {
		file->id = native->id;
		r_fs_file_free (native);
	}
	file->ptr = entry;
	return file;
}

static RList *FSP(_forensic_dir)(RFSRoot *root, const char *path, ut64 id, int view) {
	NtfsFS *fs = root->ptr;
	if (!fs->native) {
		if (!(view & (R_FS_VIEW_NORMAL | R_FS_VIEW_SPECIAL))) {
			return NULL;
		}
		root->ptr = fs->grub;
		RList *result = FSP(_dir) (root, path, id, view);
		root->ptr = fs;
		return result;
	}
	ntfs_catalog (fs);
	bool carve = !id && (view & R_FS_VIEW_DELETED);
	ut64 parent = id == UT64_MAX? ntfs_lookup (fs, path): id;
	NtfsName *directory = ntfs_named_record (fs, parent);
	if (!carve && (!directory || directory->type != 'd')) {
		return NULL;
	}
	RList *result = r_list_newf ((RListFree)r_fs_file_free);
	RListIter *iter;
	NtfsName *name;
	RList *children = carve? fs->names: ht_up_find (fs->children, parent, NULL);
	r_list_foreach (children, iter, name) {
		if (name->id == parent && !strcmp (name->name, ".")) {
			continue;
		}
		if ((!carve && (name->parent != parent || name->parent_sequence != directory->sequence))
				|| !(view & (name->flags & R_FS_FILE_DELETED? R_FS_VIEW_DELETED: R_FS_VIEW_NORMAL | R_FS_VIEW_SPECIAL))
				|| (carve && !(name->flags & R_FS_FILE_DELETED))) {
			continue;
		}
		RFSFile *file = r_fs_file_new (root, name->name);
		file->id = name->id;
		file->size = name->size;
		file->time = name->time;
		file->type = name->type;
		file->flags = name->flags;
		r_list_append (result, file);
	}
	return result;
}

static int FSP(_forensic_ranges)(RFSRoot *root, ut32 flags, RFSRangeCb cb, void *user) {
	NtfsFS *fs = root->ptr;
	if (!fs->native || !flags || (flags & ~(R_FS_RANGE_FREE | R_FS_RANGE_ALLOCATED | R_FS_RANGE_ORPHAN | R_FS_RANGE_BAD | R_FS_RANGE_UNKNOWN))) {
		return R_FS_WALK_UNSUPPORTED;
	}
	ntfs_catalog (fs);
	if ((flags & R_FS_RANGE_ORPHAN) && !fs->owners_complete) {
		return R_FS_WALK_ERROR;
	}
	RFSRange run = {0};
	ut64 cluster;
	int status = R_FS_WALK_COMPLETE;
	for (cluster = 0; cluster < fs->clusters; cluster++) {
		ut64 offset = cluster * fs->cluster_size;
		int allocated = ntfs_bit (fs, &fs->bitmap, &fs->bitmap_cache, cluster);
		ut32 state = allocated < 0? R_FS_RANGE_UNKNOWN: allocated? R_FS_RANGE_ALLOCATED: R_FS_RANGE_FREE;
		if (allocated < 0) {
			status = R_FS_WALK_ERROR;
		}
		if (ntfs_run_at (&fs->bad, offset)) {
			state = R_FS_RANGE_BAD;
		} else if ((flags & R_FS_RANGE_ORPHAN) && allocated > 0 && !ntfs_run_at (&fs->owners, offset)) {
			state |= R_FS_RANGE_ORPHAN;
		}
		if (!(flags & state)) {
			if (run.size && !cb (&run, user)) {
				return R_FS_WALK_STOPPED;
			}
			run.size = 0;
			continue;
		}
		RFSRange next = { offset, root->delta + offset, fs->cluster_size, state };
		if (ntfs_emit_range (&run, &next, cb, user) == R_FS_WALK_STOPPED) {
			return R_FS_WALK_STOPPED;
		}
	}
	return run.size && !cb (&run, user)? R_FS_WALK_STOPPED: status;
}

static bool FSP(_forensic_mount)(RFSRoot *root) {
	NtfsFS *fs = R_NEW0 (NtfsFS);
	fs->root = root;
	fs->native = ntfs_initialize (fs);
	bool mounted = false;
	if (fs->native) {
		fs->grub = grubfs_new (&FSIPTR, &root->iob);
		fs->native = fs->grub != NULL;
	} else if (fs->geometry && fs->mft.status != R_FS_WALK_ERROR) {
		mounted = FSP(_mount) (root);
		fs->grub = root->ptr;
	}
	root->ptr = fs;
	return mounted || fs->native;
}

static void FSP(_forensic_umount)(RFSRoot *root) {
	NtfsFS *fs = root->ptr;
	if (!fs) {
		return;
	}
	root->ptr = fs->grub;
	FSP(_umount) (root);
	ntfs_stream_fini (&fs->mft);
	ntfs_stream_fini (&fs->mft_bitmap);
	ntfs_stream_fini (&fs->bitmap);
	RVecNtfsRun_fini (&fs->owners);
	RVecNtfsRun_fini (&fs->bad);
	ht_up_free (fs->nodes);
	ht_up_free (fs->children);
	r_list_free (fs->names);
	free (fs);
}
