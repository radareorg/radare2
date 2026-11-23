/* radare - LGPL - Copyright 2011-2026 - pancake, MiKi (mikelloc) */

// R2R db/cmd/cmd_fs_fat

#include <r_fs.h>
#include "fs_fat.h"

typedef struct {
	RFSRoot *root;
	FatGeometry g;
	ut64 cache_at;
	ut32 cache_size;
	ut8 cache[4100];
	ut8 boot[90];
} FatFS;

typedef struct {
	ut32 cluster;
	ut32 size;
	ut64 id;
	ut64 time;
	ut8 attr;
	ut32 flags;
	char name[1024];
	ut32 current;
	ut32 index;
	ut32 checkpoint;
	ut32 power;
	ut64 readable;
	int plan_status;
	bool contiguous;
} FatEntry;

typedef bool (*FatEntryCb)(FatFS *fat, FatEntry *entry, void *user);

static bool fat_read_at(FatFS *fat, ut64 off, ut8 *buf, int len) {
	ut64 addr;
	return len >= 0 && off <= fat->g.size && (ut64)len <= fat->g.size - off
		&& !r_add_overflow_ut64 (fat->root->delta, off, &addr)
		&& fat->root->iob.read_at (fat->root->iob.io, addr, buf, len) == len;
}

static ut64 fat_cluster_offset(FatFS *fat, ut32 cluster) {
	return fat->g.data + (ut64)(cluster - 2) * fat->g.cluster_size;
}

static bool fat_valid_cluster(FatFS *fat, ut32 cluster) {
	ut32 reserved = fat->g.bits == 12? 0xff0: fat->g.bits == 16? 0xfff0: 0x0ffffff0;
	return cluster >= 2 && cluster < fat->g.clusters + 2 && cluster < reserved;
}

static bool fat_next(FatFS *fat, ut32 cluster, ut32 *next) {
	ut64 off = fat->g.bits == 12? cluster + cluster / 2: (ut64)cluster * (fat->g.bits / 8);
	ut32 width = fat->g.bits == 32? 4: 2;
	ut64 bytes = (ut64)fat->g.fat_sectors * fat->g.sector_size;
	if (off > bytes || width > bytes - off) {
		return false;
	}
	if (!fat->cache_size || off < fat->cache_at || off + width > fat->cache_at + fat->cache_size) {
		fat->cache_at = off / fat->g.sector_size * fat->g.sector_size;
		fat->cache_size = R_MIN (sizeof (fat->cache), bytes - fat->cache_at);
		if (!fat_read_at (fat, fat->g.fat + fat->cache_at, fat->cache, fat->cache_size)) {
			fat->cache_size = 0;
			return false;
		}
	}
	const ut8 *p = fat->cache + off - fat->cache_at;
	ut32 value = fat->g.bits == 32? r_read_le32 (p): r_read_le16 (p);
	if (fat->g.bits == 12 && (cluster & 1)) {
		value >>= 4;
	}
	*next = value & (fat->g.bits == 12? 0xfff: fat->g.bits == 16? 0xffff: 0x0fffffff);
	return true;
}

static bool fat_eoc(FatFS *fat, ut32 value) {
	return value >= (fat->g.bits == 12? 0xff8: fat->g.bits == 16? 0xfff8: 0x0ffffff8);
}

static ut32 fat_state(FatFS *fat, ut32 value) {
	if (!value) {
		return R_FS_RANGE_FREE;
	}
	if (value == (fat->g.bits == 12? 0xff7: fat->g.bits == 16? 0xfff7: 0x0ffffff7)) {
		return R_FS_RANGE_BAD;
	}
	return fat_valid_cluster (fat, value) || fat_eoc (fat, value)? R_FS_RANGE_ALLOCATED: R_FS_RANGE_UNKNOWN;
}

static bool fat_cluster_at(FatFS *fat, FatEntry *entry, ut32 index, ut32 *cluster) {
	if (entry->contiguous) {
		*cluster = entry->cluster + index;
		return fat_valid_cluster (fat, *cluster);
	}
	if (!entry->power || index < entry->index) {
		entry->current = entry->checkpoint = entry->cluster;
		entry->index = 0;
		entry->power = 1;
	}
	while (entry->index < index) {
		ut32 next;
		if (entry->index >= fat->g.clusters || !fat_next (fat, entry->current, &next)
				|| !fat_valid_cluster (fat, next) || next == entry->checkpoint) {
			return false;
		}
		entry->current = next;
		entry->index++;
		if (entry->index == entry->power) {
			entry->checkpoint = next;
			entry->power <<= 1;
		}
	}
	*cluster = entry->current;
	return fat_valid_cluster (fat, *cluster);
}

static bool fat_read_entry(FatFS *fat, FatEntry *entry, ut64 off, ut8 *buf, int len, ut64 *physical) {
	while (len > 0) {
		ut64 at;
		int chunk;
		if (!entry->cluster && (entry->attr & 0x10)) {
			ut64 bytes = (ut64)fat->g.root_entries * 32;
			if (off >= bytes) {
				return false;
			}
			at = fat->g.root + off;
			chunk = R_MIN ((ut64)len, bytes - off);
		} else {
			ut32 cluster;
			if (off / fat->g.cluster_size >= fat->g.clusters
					|| !fat_cluster_at (fat, entry, off / fat->g.cluster_size, &cluster)) {
				return false;
			}
			at = fat_cluster_offset (fat, cluster) + off % fat->g.cluster_size;
			chunk = R_MIN ((ut32)len, fat->g.cluster_size - off % fat->g.cluster_size);
		}
		if (!fat_read_at (fat, at, buf, chunk)) {
			return false;
		}
		if (physical) {
			*physical = at;
			physical = NULL;
		}
		buf += chunk;
		off += chunk;
		len -= chunk;
	}
	return true;
}

static ut8 fat_checksum(const ut8 *name) {
	ut8 sum = 0;
	int i;
	for (i = 0; i < 11; i++) {
		sum = ((sum >> 1) | (sum << 7)) + name[i];
	}
	return sum;
}

static bool fat_short_char(ut8 ch) {
	return ch >= 0x20 && ch != 0x7f && !strchr ("\"*+,./:;<=>?[\\]|", ch);
}

static bool fat_name_checksum(const ut8 *raw, int checksum) {
	if (raw[0] != 0xe5) {
		return checksum == fat_checksum (raw);
	}
	ut8 first = checksum;
	int i;
	for (i = 10; i > 0; i--) {
		first -= raw[i];
		first = (first << 1) | (first >> 7);
	}
	return first != 0xe5 && first != ' ' && (first == 5 || fat_short_char (first));
}

static bool fat_long_name(FatEntry *entry, const ut8 *lfn, int units) {
	int length = 0;
	while (length < units && r_read_le16 (lfn + length * 2)) {
		length++;
	}
	if (!length || length > 255 || (length <= 2 && r_read_le16 (lfn) == '.'
			&& (length == 1 || r_read_le16 (lfn + 2) == '.'))) {
		return false;
	}
	int i;
	for (i = length + 1; i < units; i++) {
		if (r_read_le16 (lfn + i * 2) != 0xffff) {
			return false;
		}
	}
	for (i = 0; i < length; i++) {
		ut16 rune = r_read_le16 (lfn + i * 2);
		if (rune >= 0xd800 && rune <= 0xdbff) {
			if (++i >= length) {
				return false;
			}
			rune = r_read_le16 (lfn + i * 2);
			if (rune < 0xdc00 || rune > 0xdfff) {
				return false;
			}
		} else if ((rune >= 0xdc00 && rune <= 0xdfff) || rune < 0x20 || rune == 0xffff
				|| (rune < 0x80 && strchr ("\"*/:<>?\\|", rune))) {
			return false;
		}
	}
	int bytes = r_str_utf16_to_utf8 ((ut8 *)entry->name, sizeof (entry->name), lfn, length * 2, false);
	return bytes > 0;
}

static void fat_lfn_part(ut8 *dst, const ut8 *raw) {
	memcpy (dst, raw + 1, 10);
	memcpy (dst + 10, raw + 14, 12);
	memcpy (dst + 22, raw + 28, 4);
}

static bool fat_decode(FatFS *fat, const ut8 *raw, ut64 id, FatEntry *entry) {
	if (!raw[0] || raw[0] == ' ' || raw[11] == 0x0f || (raw[11] & 0xc8)) {
		return false;
	}
	*entry = (FatEntry) {
		.cluster = r_read_le16 (raw + 26),
		.size = r_read_le32 (raw + 28),
		.id = id,
		.attr = raw[11],
		.flags = raw[0] == 0xe5? R_FS_FILE_DELETED: 0,
	};
	if (fat->g.bits == 32) {
		entry->cluster |= (r_read_le16 (raw + 20) & 0xfff) << 16;
	}
	if (r_read_le16 (raw + 24)) {
		entry->time = r_time_dos_today (r_read_le32 (raw + 22), 0);
	}
	int length = 0, i;
	for (i = 0; i < 11; i++) {
		if (i == 8 && raw[8] != ' ') {
			entry->name[length++] = '.';
		}
		if (raw[i] != ' ') {
			ut8 ch = i == 0 && raw[i] == 5? 0xe5: raw[i];
			if (i == 0 && (entry->flags & R_FS_FILE_DELETED)) {
				entry->name[length++] = '_';
			} else if (ch >= 0x80) {
				length += snprintf (entry->name + length, sizeof (entry->name) - length, "\\x%02x", ch);
			} else if (fat_short_char (ch) || ((entry->attr & 0x10) && ch == '.' && i < 2)) {
				entry->name[length++] = tolower (ch);
			} else {
				return false;
			}
		}
	}
	entry->name[length] = 0;
	return *entry->name != 0;
}

static int fat_iterate(FatFS *fat, FatEntry *dir, int view, FatEntryCb cb, void *user) {
	ut8 raw[32], lfn[520];
	int slot = 0, slots = 0, checksum = -1, deleted_slots = 0;
	ut64 limit = dir->cluster? (ut64)fat->g.clusters * fat->g.cluster_size: (ut64)fat->g.root_entries * 32;
	ut64 off;
	fat->cache_size = 0;
	for (off = 0; off < limit; off += 32) {
		ut64 physical;
		if (!fat_read_entry (fat, dir, off, raw, sizeof (raw), &physical)) {
			ut32 next;
			return off && !(off % fat->g.cluster_size) && fat_next (fat, dir->current, &next)
				&& fat_eoc (fat, next)? 0: -1;
		}
		if (!raw[0]) {
			return 0;
		}
		if (raw[11] == 0x0f) {
			if (raw[0] == 0xe5) {
				if (!deleted_slots) {
					checksum = raw[13];
				} else if (checksum != raw[13]) {
					deleted_slots = 21;
				}
				slot = slots = 0;
				if (++deleted_slots <= 20 && !raw[12] && !r_read_le16 (raw + 26)) {
					fat_lfn_part (lfn + (20 - deleted_slots) * 26, raw);
				} else {
					deleted_slots = 21;
				}
				continue;
			}
			deleted_slots = 0;
			int id = raw[0] & 31;
			if (raw[0] & 0x40) {
				slot = slots = id;
				checksum = raw[13];
			}
			if (!id || id > 20 || id != slot || (raw[0] & 0xa0)
					|| raw[12] || r_read_le16 (raw + 26) || raw[13] != checksum) {
				slot = slots = 0;
				checksum = -1;
				continue;
			}
			fat_lfn_part (lfn + --slot * 26, raw);
			continue;
		}
		FatEntry entry;
		if (fat_decode (fat, raw, physical, &entry)
				&& (view & ((entry.flags & R_FS_FILE_DELETED)? R_FS_VIEW_DELETED: R_FS_VIEW_NORMAL))) {
			if (fat_name_checksum (raw, checksum)) {
				bool restored = false;
				if ((entry.flags & R_FS_FILE_DELETED) && deleted_slots > 0 && deleted_slots <= 20) {
					restored = fat_long_name (&entry, lfn + (20 - deleted_slots) * 26, deleted_slots * 13);
				} else if (slots && !slot && !deleted_slots) {
					restored = fat_long_name (&entry, lfn, slots * 13);
				}
				if (restored && (entry.flags & R_FS_FILE_DELETED)) {
					entry.flags |= R_FS_FILE_HEURISTIC;
				}
			}
			if (cb (fat, &entry, user)) {
				return 1;
			}
		}
		slot = slots = deleted_slots = 0;
		checksum = -1;
	}
	return dir->cluster? -1: 0;
}

typedef struct {
	const char *name;
	FatEntry *entry;
} FatLookup;

static bool fat_lookup_cb(FatFS *fat, FatEntry *entry, void *user) {
	FatLookup *lookup = user;
	if (lookup->name? !r_str_casecmp (entry->name, lookup->name): entry->id == lookup->entry->id) {
		*lookup->entry = *entry;
		return true;
	}
	return false;
}

static bool fat_entry_id(FatFS *fat, ut64 id, FatEntry *entry) {
	ut8 raw[32];
	if ((id & 31) || id < fat->g.root || !fat_read_at (fat, id, raw, sizeof (raw)) || !fat_decode (fat, raw, id, entry)) {
		return false;
	}
	FatEntry dir = { .attr = 0x10, .id = UT64_MAX };
	if (id >= fat->g.data) {
		dir.cluster = 2 + (id - fat->g.data) / fat->g.cluster_size;
	}
	FatLookup lookup = { NULL, entry };
	fat_iterate (fat, &dir, R_FS_VIEW_ALL, fat_lookup_cb, &lookup);
	return true;
}

static bool fat_lookup(FatFS *fat, const char *path, FatEntry *entry) {
	*entry = (FatEntry) { .cluster = fat->g.root_cluster, .attr = 0x10, .id = UT64_MAX };
	char *copy = strdup (path), *state = NULL;
	if (!copy) {
		return false;
	}
	char *part = r_str_tok_r (copy, "/", &state);
	bool ok = true;
	while (part) {
		FatEntry dir = *entry;
		FatLookup lookup = { part, entry };
		if (!(dir.attr & 0x10) || fat_iterate (fat, &dir, R_FS_VIEW_NORMAL, fat_lookup_cb, &lookup) != 1) {
			ok = false;
			break;
		}
		part = r_str_tok_r (NULL, "/", &state);
	}
	free (copy);
	return ok;
}

static void fat_fill_file(FatFS *fat, RFSFile *file, FatEntry *entry) {
	file->type = entry->attr & 0x10? 'd': 'f';
	file->size = entry->size;
	file->time = entry->time;
	file->id = entry->id;
	file->flags = entry->flags;
	file->off = fat_valid_cluster (fat, entry->cluster)
		? fat->root->delta + fat_cluster_offset (fat, entry->cluster): UT64_MAX;
}

static RFSFile *fat_file(FatFS *fat, const char *path, FatEntry *entry) {
	if (entry->size && !fat_valid_cluster (fat, entry->cluster)) {
		entry->flags |= R_FS_FILE_PARTIAL;
	}
	RFSFile *file = r_fs_file_new (fat->root, path);
	FatEntry *handle = R_NEW (FatEntry);
	*handle = *entry;
	file->ptr = handle;
	fat_fill_file (fat, file, handle);
	return file;
}

static RFSFile *fat_open(RFSRoot *root, const char *path, bool create) {
	FatFS *fat = root->ptr;
	FatEntry entry;
	return !create && fat_lookup (fat, path, &entry) && !(entry.attr & 0x10)
		? fat_file (fat, path, &entry): NULL;
}

static RFSFile *fat_open_id(RFSRoot *root, ut64 id, ut32 flags) {
	FatFS *fat = root->ptr;
	FatEntry entry;
	if (flags > R_FS_OPEN_CONTIGUOUS || !fat_entry_id (fat, id, &entry)) {
		return NULL;
	}
	if (flags == R_FS_OPEN_CONTIGUOUS) {
		if (!(entry.flags & R_FS_FILE_DELETED) || (entry.attr & 0x10)) {
			return NULL;
		}
		entry.contiguous = true;
		entry.flags |= R_FS_FILE_HEURISTIC;
	}
	return fat_file (fat, entry.name, &entry);
}

static int fat_plan(RFSFile *file);

static int fat_read(RFSFile *file, ut64 off, int len) {
	FatFS *fat = file->root->ptr;
	FatEntry *entry = file->ptr;
	if (entry->attr & 0x10) {
		return -1;
	}
	if (off >= entry->size) {
		return 0;
	}
	ut64 readable = entry->size;
	if ((entry->flags & R_FS_FILE_DELETED) || entry->size > fat->g.cluster_size) {
		fat_plan (file);
		readable = entry->readable;
	}
	if (off >= readable) {
		return -1;
	}
	fat->cache_size = 0;
	len = R_MIN ((ut64)len, readable - off);
	if (!fat_read_entry (fat, entry, off, file->data, len, NULL)) {
		file->flags |= R_FS_FILE_PARTIAL;
		return -1;
	}
	return len;
}

static void fat_close(RFSFile *file) {
	R_FREE (file->ptr);
}

static bool fat_dir_cb(FatFS *fat, FatEntry *entry, void *user) {
	RFSFile *file = r_fs_file_new (NULL, entry->name);
	fat_fill_file (fat, file, entry);
	r_list_append ((RList *)user, file);
	return false;
}

static RList *fat_dir(RFSRoot *root, const char *path, ut64 id, int view) {
	FatFS *fat = root->ptr;
	FatEntry dir;
	if (!(id == UT64_MAX? fat_lookup (fat, path, &dir): fat_entry_id (fat, id, &dir))
			|| !(dir.attr & 0x10) || (!dir.cluster && dir.id != UT64_MAX)) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	fat_iterate (fat, &dir, view, fat_dir_cb, list);
	return list;
}

static int fat_walk(RFSFile *file, ut64 remaining, RBitmap *owners, RFSRangeCb cb, void *user) {
	FatFS *fat = file->root->ptr;
	FatEntry *entry = file->ptr;
	bool directory = entry->attr & 0x10;
	if (!remaining) {
		return R_FS_WALK_COMPLETE;
	}
	if (directory && !entry->cluster) {
		if (entry->id != UT64_MAX) {
			return R_FS_WALK_ERROR;
		}
		RFSRange range = { 0, fat->root->delta + fat->g.root, (ut64)fat->g.root_entries * 32, R_FS_RANGE_ALLOCATED };
		return cb (&range, user)? R_FS_WALK_COMPLETE: R_FS_WALK_STOPPED;
	}
	RBitmap *seen = r_bitmap_new (fat->g.clusters + 2);
	if (!seen) {
		return R_FS_WALK_ERROR;
	}
	RFSRange run = {0};
	ut32 cluster = entry->cluster;
	int status = R_FS_WALK_COMPLETE;
	fat->cache_size = 0;
	while (remaining) {
		ut32 next;
		if (!fat_valid_cluster (fat, cluster) || r_bitmap_test (seen, cluster) || !fat_next (fat, cluster, &next)) {
			status = R_FS_WALK_ERROR;
			break;
		}
		ut32 flags = fat_state (fat, next);
		if ((owners && r_bitmap_test (owners, cluster)) || (entry->contiguous && flags == R_FS_RANGE_ALLOCATED)) {
			file->flags |= R_FS_FILE_CONFLICT;
			status = R_FS_WALK_ERROR;
			break;
		}
		if (flags == R_FS_RANGE_BAD || flags == R_FS_RANGE_UNKNOWN) {
			status = R_FS_WALK_ERROR;
			break;
		}
		r_bitmap_set (seen, cluster);
		ut64 physical = fat->root->delta + fat_cluster_offset (fat, cluster);
		ut64 size = R_MIN (remaining, fat->g.cluster_size);
		if (entry->contiguous) {
			flags |= R_FS_RANGE_HEURISTIC;
		}
		if (run.size && (run.physical + run.size != physical || run.flags != flags)) {
			if (!cb (&run, user)) {
				status = R_FS_WALK_STOPPED;
				break;
			}
			run.logical += run.size;
			run.size = 0;
		}
		if (!run.size) {
			run.physical = physical;
			run.flags = flags;
		}
		run.size += size;
		remaining -= size;
		if (directory && fat_eoc (fat, next)) {
			break;
		}
		cluster = entry->contiguous? cluster + 1: next;
	}
	if (status != R_FS_WALK_STOPPED && run.size && !cb (&run, user)) {
		status = R_FS_WALK_STOPPED;
	}
	if (status == R_FS_WALK_ERROR) {
		file->flags |= R_FS_FILE_PARTIAL;
	}
	r_bitmap_free (seen);
	return status;
}

typedef struct {
	RBitmap *used;
	RBitmap *directories;
	int depth;
	int budget;
	bool ok;
} FatOwners;

static bool fat_mark_chain(FatFS *fat, FatEntry *entry, RBitmap *used) {
	ut32 cluster = entry->cluster;
	if (!cluster && !entry->size) {
		return !(entry->attr & 0x10) || entry->id == UT64_MAX;
	}
	while (fat_valid_cluster (fat, cluster)) {
		if (r_bitmap_test (used, cluster)) {
			return true;
		}
		r_bitmap_set (used, cluster);
		ut32 next;
		if (!fat_next (fat, cluster, &next)) {
			return false;
		}
		if (fat_eoc (fat, next)) {
			return true;
		}
		cluster = next;
	}
	return false;
}

static bool fat_owner_cb(FatFS *fat, FatEntry *entry, void *user) {
	FatOwners *owners = user;
	if (!strcmp (entry->name, ".") || !strcmp (entry->name, "..")) {
		return false;
	}
	if (--owners->budget < 0 || !fat_mark_chain (fat, entry, owners->used)) {
		owners->ok = false;
		return true;
	}
	if ((entry->attr & 0x10) && !r_bitmap_test (owners->directories, entry->cluster)) {
		r_bitmap_set (owners->directories, entry->cluster);
		if (++owners->depth > 64 || fat_iterate (fat, entry, R_FS_VIEW_NORMAL, fat_owner_cb, owners) < 0) {
			owners->ok = false;
		}
		owners->depth--;
	}
	return !owners->ok;
}

static RBitmap *fat_owners(FatFS *fat) {
	FatOwners owners = {
		.used = r_bitmap_new (fat->g.clusters + 2),
		.directories = r_bitmap_new (fat->g.clusters + 2),
		.budget = 0x100000,
		.ok = true,
	};
	FatEntry root = { .cluster = fat->g.root_cluster, .attr = 0x10, .id = UT64_MAX };
	fat->cache_size = 0;
	if (!owners.used || !owners.directories || !fat_mark_chain (fat, &root, owners.used)
			|| fat_iterate (fat, &root, R_FS_VIEW_NORMAL, fat_owner_cb, &owners) < 0 || !owners.ok) {
		r_bitmap_free (owners.used);
		owners.used = NULL;
	}
	r_bitmap_free (owners.directories);
	return owners.used;
}

static bool fat_count_range(const RFSRange *range, void *user) {
	ut64 *size = user;
	*size += range->size;
	return true;
}

static int fat_plan(RFSFile *file) {
	FatFS *fat = file->root->ptr;
	FatEntry *entry = file->ptr;
	if (!entry->plan_status) {
		RBitmap *owners = entry->flags & R_FS_FILE_DELETED? fat_owners (fat): NULL;
		entry->plan_status = R_FS_WALK_ERROR;
		if (!(entry->flags & R_FS_FILE_DELETED) || owners) {
			entry->plan_status = fat_walk (file, entry->attr & 0x10? UT64_MAX: entry->size,
				owners, fat_count_range, &entry->readable);
		}
		if (entry->plan_status != R_FS_WALK_COMPLETE) {
			file->flags |= R_FS_FILE_PARTIAL;
		}
		r_bitmap_free (owners);
	}
	return entry->plan_status;
}

static int fat_extents(RFSFile *file, RFSRangeCb cb, void *user) {
	FatEntry *entry = file->ptr;
	int status = fat_plan (file);
	if (entry->readable) {
		int result = fat_walk (file, entry->readable, NULL, cb, user);
		if (result != R_FS_WALK_COMPLETE) {
			return result;
		}
	}
	return status;
}

static int fat_ranges(RFSRoot *root, ut32 flags, RFSRangeCb cb, void *user) {
	FatFS *fat = root->ptr;
	ut32 states = R_FS_RANGE_FREE | R_FS_RANGE_ALLOCATED | R_FS_RANGE_ORPHAN | R_FS_RANGE_BAD | R_FS_RANGE_UNKNOWN;
	if (!flags || (flags & ~states)) {
		return R_FS_WALK_ERROR;
	}
	RBitmap *used = flags & R_FS_RANGE_ORPHAN? fat_owners (fat): NULL;
	if ((flags & R_FS_RANGE_ORPHAN) && !used) {
		return R_FS_WALK_ERROR;
	}
	RFSRange run = {0};
	ut32 cluster;
	int status = R_FS_WALK_COMPLETE;
	fat->cache_size = 0;
	for (cluster = 2; cluster < fat->g.clusters + 2; cluster++) {
		ut32 next;
		if (!fat_next (fat, cluster, &next)) {
			status = R_FS_WALK_ERROR;
			break;
		}
		ut32 state = fat_valid_cluster (fat, cluster)? fat_state (fat, next): R_FS_RANGE_UNKNOWN;
		if (used && state == R_FS_RANGE_ALLOCATED && !r_bitmap_test (used, cluster)) {
			state |= R_FS_RANGE_ORPHAN;
		}
		ut64 logical = fat_cluster_offset (fat, cluster);
		if (run.size && (!(state & flags) || run.flags != state || run.logical + run.size != logical)) {
			if (!cb (&run, user)) {
				status = R_FS_WALK_STOPPED;
				break;
			}
			run.size = 0;
		}
		if (state & flags) {
			if (!run.size) {
				run.logical = logical;
				run.physical = root->delta + logical;
				run.flags = state;
			}
			run.size += fat->g.cluster_size;
		}
	}
	if (status == R_FS_WALK_COMPLETE && run.size && !cb (&run, user)) {
		status = R_FS_WALK_STOPPED;
	}
	r_bitmap_free (used);
	return status;
}

static bool fat_mount(RFSRoot *root) {
	ut8 boot[512];
	FatGeometry g;
	if (root->iob.read_at (root->iob.io, root->delta, boot, sizeof (boot)) != sizeof (boot)
			|| !fat_geometry (boot, &g) || root->delta > UT64_MAX - g.size) {
		return false;
	}
	RIOMap *map = root->iob.map_get_at? root->iob.map_get_at (root->iob.io, root->delta): NULL;
	if (map && g.size > r_itv_end (map->itv) - root->delta) {
		return false;
	}
	FatFS *fat = R_NEW0 (FatFS);
	fat->root = root;
	fat->g = g;
	memcpy (fat->boot, boot, sizeof (fat->boot));
	root->ptr = fat;
	return true;
}

static void fat_umount(RFSRoot *root) {
	R_FREE (root->ptr);
}

static void fat_details(RFSRoot *root, RStrBuf *sb) {
	FatFS *fat = root->ptr;
	FatGeometry *g = &fat->g;
	const ut8 *b = fat->boot;
	int base = g->bits == 32? 64: 36;
	char *label = r_str_ndup ((const char *)b + base + 7, 11);
	char *oem = r_str_ndup ((const char *)b + 3, 8);
	char *type = r_str_ndup ((const char *)b + base + 18, 8);
	r_str_trim_tail (label);
	r_str_trim_tail (oem);
	r_str_trim_tail (type);
	r_strbuf_appendf (sb, "Filesystem Type: FAT%u\n", g->bits);
	r_strbuf_appendf (sb, "Volume Label: %s\nOEM Name: %s\n", label, oem);
	r_strbuf_appendf (sb, "Serial Number: %08X\nFS Type String: %s\n", r_read_le32 (b + base + 3), type);
	r_strbuf_appendf (sb, "Media Type: 0x%02x\nBytes per Sector: %u\n", b[21], g->sector_size);
	r_strbuf_appendf (sb, "Sectors per Cluster: %u\nCluster Size: %u bytes\n", b[13], g->cluster_size);
	r_strbuf_appendf (sb, "Reserved Sectors: %u\nNumber of FATs: %u\n", g->reserved, g->fats);
	r_strbuf_appendf (sb, "Sectors per FAT: %u\nFAT Size: %"PFMT64u" bytes\n", g->fat_sectors, (ut64)g->fat_sectors * g->sector_size);
	if (g->bits == 32) {
		r_strbuf_appendf (sb, "Root Directory Cluster: %u\n", g->root_cluster);
	} else {
		r_strbuf_appendf (sb, "Root Directory Entries: %u\nRoot Directory Sectors: %u\n", g->root_entries, g->root_sectors);
	}
	r_strbuf_appendf (sb, "Total Sectors: %u\nData Sectors: %"PFMT64u"\n", g->sectors, (g->size - g->data) / g->sector_size);
	r_strbuf_appendf (sb, "Total Clusters: %u\nFirst Data Sector: %"PFMT64u"\n", g->clusters, g->data / g->sector_size);
	r_strbuf_appendf (sb, "Total Size: %"PFMT64u" bytes (%.2f MB)\n", g->size, (double)g->size / (1024 * 1024));
	free (label);
	free (oem);
	free (type);
}

RFSPlugin r_fs_plugin_fat = {
	.meta = {
		.name = "fat",
		.author = "pancake",
		.desc = "FAT12/16/32 and VFAT filesystem",
		.license = "LGPL-3.0-only",
	},
	.open = fat_open,
	.open_id = fat_open_id,
	.extents = fat_extents,
	.ranges = fat_ranges,
	.read = fat_read,
	.close = fat_close,
	.dir = fat_dir,
	.mount = fat_mount,
	.umount = fat_umount,
	.details = fat_details,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_fat,
	.version = R2_VERSION
};
#endif
