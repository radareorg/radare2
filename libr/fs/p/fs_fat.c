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
	bool deleted;
	char name[1024];
	ut32 current;
	ut32 index;
	ut32 checkpoint;
	ut32 power;
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

static bool fat_cluster_at(FatFS *fat, FatEntry *entry, ut32 index, ut32 *cluster) {
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

static int fat_iterate(FatFS *fat, FatEntry *dir, int view, FatEntryCb cb, void *user) {
	ut8 raw[32], lfn[520];
	int slot = 0, slots = 0, checksum = -1;
	ut64 limit = dir->cluster? (ut64)fat->g.clusters * fat->g.cluster_size: (ut64)fat->g.root_entries * 32;
	ut64 off;
	fat->cache_size = 0;
	for (off = 0; off < limit; off += 32) {
		ut64 physical;
		if (!fat_read_entry (fat, dir, off, raw, sizeof (raw), &physical)) {
			return -1;
		}
		if (!raw[0]) {
			return 0;
		}
		if (raw[11] == 0x0f) {
			int id = raw[0] & 31;
			if (raw[0] & 0x40) {
				slot = slots = id;
				checksum = raw[13];
				memset (lfn, 0xff, sizeof (lfn));
			}
			if (raw[0] == 0xe5 || !id || id > 20 || id != slot
					|| raw[12] || r_read_le16 (raw + 26) || raw[13] != checksum) {
				slot = slots = 0;
				checksum = -1;
				continue;
			}
			ut8 *p = lfn + --slot * 26;
			memcpy (p, raw + 1, 10);
			memcpy (p + 10, raw + 14, 12);
			memcpy (p + 22, raw + 28, 4);
			continue;
		}
		FatEntry entry = {
			.cluster = r_read_le16 (raw + 26),
			.size = r_read_le32 (raw + 28),
			.id = physical,
			.attr = raw[11],
			.deleted = raw[0] == 0xe5,
		};
		if (fat->g.bits == 32) {
			entry.cluster |= (r_read_le16 (raw + 20) & 0xfff) << 16;
		}
		if (r_read_le16 (raw + 24)) {
			entry.time = r_time_dos_today (r_read_le32 (raw + 22), 0);
		}
		if (!(entry.attr & 0xc8) && (!entry.deleted || (view & R_FS_VIEW_DELETED))) {
			int length = 0, i;
			if (slots && !slot && checksum == fat_checksum (raw)) {
				while (length < R_MIN (slots * 13, 255)
						&& r_read_le16 (lfn + length * 2) && r_read_le16 (lfn + length * 2) != 0xffff) {
					length++;
				}
				length = r_str_utf16_to_utf8 ((ut8 *)entry.name, sizeof (entry.name) - 1, lfn, length * 2, false);
			}
			if (length <= 0) {
				length = 0;
				for (i = 0; i < 11; i++) {
					if (i == 8 && raw[8] != ' ') {
						entry.name[length++] = '.';
					}
					if (raw[i] != ' ') {
						entry.name[length++] = i == 0 && raw[i] == 5? 0xe5: tolower (raw[i]);
					}
				}
			}
			entry.name[length] = 0;
			if (*entry.name && !strchr (entry.name, '/') && !strchr (entry.name, '\\')
					&& cb (fat, &entry, user)) {
				return 1;
			}
		}
		slot = slots = 0;
		checksum = -1;
	}
	return -1;
}

typedef struct {
	const char *name;
	FatEntry *entry;
} FatLookup;

static bool fat_lookup_cb(FatFS *fat, FatEntry *entry, void *user) {
	FatLookup *lookup = user;
	if (!r_str_casecmp (entry->name, lookup->name)) {
		*lookup->entry = *entry;
		return true;
	}
	return false;
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
		if (!(dir.attr & 0x10) || fat_iterate (fat, &dir, R_FS_VIEW_ALL, fat_lookup_cb, &lookup) != 1) {
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
	file->off = fat_valid_cluster (fat, entry->cluster)
		? fat->root->delta + fat_cluster_offset (fat, entry->cluster): UT64_MAX;
}

static RFSFile *fat_open(RFSRoot *root, const char *path, bool create) {
	FatFS *fat = root->ptr;
	FatEntry entry;
	if (create || !fat_lookup (fat, path, &entry) || (entry.attr & 0x10)
			|| (entry.size && !fat_valid_cluster (fat, entry.cluster))) {
		return NULL;
	}
	RFSFile *file = r_fs_file_new (root, path);
	FatEntry *handle = R_NEW (FatEntry);
	*handle = entry;
	file->ptr = handle;
	fat_fill_file (fat, file, handle);
	return file;
}

static int fat_read(RFSFile *file, ut64 off, int len) {
	FatFS *fat = file->root->ptr;
	FatEntry *entry = file->ptr;
	fat->cache_size = 0;
	if (off >= entry->size) {
		return 0;
	}
	len = R_MIN ((ut64)len, entry->size - off);
	return fat_read_entry (fat, entry, off, file->data, len, NULL)? len: -1;
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

static RList *fat_dir(RFSRoot *root, const char *path, int view) {
	FatFS *fat = root->ptr;
	FatEntry dir;
	if (!fat_lookup (fat, path, &dir) || !(dir.attr & 0x10)) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	fat_iterate (fat, &dir, view, fat_dir_cb, list);
	return list;
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
