/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_FS_FAT_H
#define R_FS_FAT_H

typedef struct {
	ut64 fat;
	ut64 root;
	ut64 data;
	ut64 size;
	ut32 sector_size;
	ut32 cluster_size;
	ut32 clusters;
	ut32 root_cluster;
	ut32 root_entries;
	ut32 root_sectors;
	ut32 fat_sectors;
	ut32 sectors;
	ut32 reserved;
	ut8 bits;
	ut8 fats;
	ut8 active;
} FatGeometry;

static bool fat_geometry(const ut8 *b, FatGeometry *g) {
	memset (g, 0, sizeof (*g));
	if (r_read_le16 (b + 510) != 0xaa55) {
		return false;
	}
	g->sector_size = r_read_le16 (b + 11);
	ut32 spc = b[13];
	if (g->sector_size < 512 || g->sector_size > 4096
			|| (g->sector_size & (g->sector_size - 1))
			|| !spc || spc > 128 || (spc & (spc - 1))) {
		return false;
	}
	g->reserved = r_read_le16 (b + 14);
	g->fats = b[16];
	g->root_entries = r_read_le16 (b + 17);
	g->sectors = r_read_le16 (b + 19);
	if (!g->sectors) {
		g->sectors = r_read_le32 (b + 32);
	}
	ut32 fat16 = r_read_le16 (b + 22);
	g->fat_sectors = fat16? fat16: r_read_le32 (b + 36);
	g->root_sectors = ((ut64)g->root_entries * 32 + g->sector_size - 1) / g->sector_size;
	ut64 overhead = g->reserved + (ut64)g->fats * g->fat_sectors + g->root_sectors;
	if (!g->reserved || !g->fats || !g->fat_sectors || overhead >= g->sectors) {
		return false;
	}
	g->clusters = (g->sectors - overhead) / spc;
	g->bits = g->clusters < 4085? 12: g->clusters < 65525? 16: 32;
	if (!g->clusters || g->clusters >= 0x0ffffff0
			|| ((ut64)g->clusters + 2) * g->bits > (ut64)g->fat_sectors * g->sector_size * 8) {
		return false;
	}
	if (g->bits == 32) {
		g->root_cluster = r_read_le32 (b + 44) & 0x0fffffff;
		ut16 flags = r_read_le16 (b + 40);
		g->active = flags & 0x80? flags & 15: 0;
		if (fat16 || g->root_entries || r_read_le16 (b + 42)
				|| g->active >= g->fats || g->root_cluster < 2
				|| g->root_cluster >= g->clusters + 2) {
			return false;
		}
	} else if (!fat16 || !g->root_entries) {
		return false;
	}
	g->cluster_size = spc * g->sector_size;
	g->fat = (g->reserved + (ut64)g->active * g->fat_sectors) * g->sector_size;
	g->root = (g->reserved + (ut64)g->fats * g->fat_sectors) * g->sector_size;
	g->data = overhead * g->sector_size;
	g->size = (ut64)g->sectors * g->sector_size;
	return true;
}

#endif
