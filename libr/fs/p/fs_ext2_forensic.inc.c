/* radare - LGPL - Copyright 2026 - pancake */

static ut32 ext2_crc32c(ut32 crc, const ut8 *data, ut32 size) {
	static const ut32 table[16] = {
		0, 0x105ec76f, 0x20bd8ede, 0x30e349b1, 0x417b1dbc, 0x5125dad3, 0x61c69362, 0x7198540d,
		0x82f63b78, 0x92a8fc17, 0xa24bb5a6, 0xb21572c9, 0xc38d26c4, 0xd3d3e1ab, 0xe330a81a, 0xf36e6f75
	};
	ut32 i;
	for (i = 0; i < size; i++) {
		crc ^= data[i];
		crc = (crc >> 4) ^ table[crc & 15];
		crc = (crc >> 4) ^ table[crc & 15];
	}
	return crc;
}

static ut16 ext2_crc16(ut16 crc, const ut8 *data, ut32 size) {
	static const ut16 table[16] = {
		0, 0xcc01, 0xd801, 0x1400, 0xf001, 0x3c00, 0x2800, 0xe401,
		0xa001, 0x6c00, 0x7800, 0xb401, 0x5000, 0x9c01, 0x8801, 0x4400
	};
	ut32 i;
	for (i = 0; i < size; i++) {
		crc ^= data[i];
		crc = (crc >> 4) ^ table[crc & 15];
		crc = (crc >> 4) ^ table[crc & 15];
	}
	return crc;
}

typedef struct {
	ut8 *data;
	ut32 group;
	bool inode, valid;
	RBitset *metadata;
} Ext2BitmapCache;

typedef struct {
	RFSRoot *root;
	ut64 blocks;
	ut32 inodes, first, block_size, blocks_per_group, inodes_per_group;
	ut32 groups, inode_size, incompat, ro_compat, reserved_gdt, first_inode, creator_os;
	ut32 descriptor_size, checksum_seed;
	ut8 uuid[16];
	Ext2BitmapCache *cache;
} Ext2Geometry;

typedef struct {
	GrubFS *grub;
	ut8 inode[128];
	bool recovery;
	bool contiguous;
	RBitset *owners;
	Ext2BitmapCache bitmap;
	bool checked;
	bool sparse_known;
	bool planned;
	ut64 readable;
} Ext2File;

static bool ext2_disk(Ext2Geometry *g, ut64 offset, ut8 *buf, int len) {
	ut64 size = (ut64)g->blocks * g->block_size;
	return len >= 0 && offset <= size && (ut64)len <= size - offset
		&& g->root->delta <= UT64_MAX - offset
		&& g->root->iob.read_at (g->root->iob.io, g->root->delta + offset, buf, len) == len;
}

static bool ext2_geometry(RFSRoot *root, Ext2Geometry *g) {
	memset (g, 0, sizeof (*g));
	ut8 sb[1024];
	if (root->delta > UT64_MAX - 2048 || root->iob.read_at (root->iob.io, root->delta + 1024, sb, sizeof (sb)) != sizeof (sb)
			|| r_read_le16 (sb + 56) != 0xef53 || r_read_le32 (sb + 24) > 6) {
		return false;
	}
	g->root = root;
	g->inodes = r_read_le32 (sb);
	g->blocks = r_read_le32 (sb + 4);
	g->first = r_read_le32 (sb + 20);
	g->block_size = 1024U << r_read_le32 (sb + 24);
	g->blocks_per_group = r_read_le32 (sb + 32);
	g->inodes_per_group = r_read_le32 (sb + 40);
	g->inode_size = r_read_le32 (sb + 76)? r_read_le16 (sb + 88): 128;
	g->first_inode = r_read_le32 (sb + 76)? r_read_le32 (sb + 84): 11;
	g->first_inode = R_MAX (g->first_inode, 11);
	g->creator_os = r_read_le32 (sb + 72);
	g->incompat = r_read_le32 (sb + 96);
	g->ro_compat = r_read_le32 (sb + 100);
	if (g->incompat & 128) {
		g->blocks |= (ut64)r_read_le32 (sb + 336) << 32;
	}
	g->descriptor_size = g->incompat & 128? r_read_le16 (sb + 254): 32;
	memcpy (g->uuid, sb + 104, 16);
	g->checksum_seed = g->incompat & 0x2000? r_read_le32 (sb + 624): ext2_crc32c (UT32_MAX, g->uuid, 16);
	if ((g->ro_compat & 0x400) && (sb[373] != 1 || ext2_crc32c (UT32_MAX, sb, 1020) != r_read_le32 (sb + 1020))) {
		R_LOG_WARN ("Invalid ext4 superblock checksum");
		return false;
	}
	g->reserved_gdt = r_read_le16 (sb + 206);
	if (!g->blocks_per_group || !g->inodes_per_group || g->blocks_per_group > g->block_size * 8
			|| g->inodes_per_group > g->block_size * 8 || g->first >= g->blocks || !g->inodes
			|| ((g->ro_compat & 0x400) && ((g->blocks_per_group | g->inodes_per_group) & 7))
			|| g->first != (g->block_size == 1024? 1: 0)
			|| g->inode_size < 128 || g->inode_size > g->block_size || (g->inode_size & (g->inode_size - 1))
			|| g->descriptor_size < (g->incompat & 128? 64: 32) || g->descriptor_size > g->block_size
			|| (g->descriptor_size & 7) || (g->incompat & ~(2U | 4 | 0x40 | 0x80 | 0x200 | 0x2000))
			|| (g->ro_compat & ~(7U | 8 | 16 | 32 | 64 | 256 | 0x400 | 0x1000 | 0x2000 | 0x8000 | 0x10000))
			|| (r_read_le32 (sb + 92) & 0x200) || g->blocks > (UT64_MAX - root->delta) / g->block_size) {
		return false;
	}
	ut64 groups = (g->blocks - g->first - 1) / g->blocks_per_group + 1;
	if (groups > UT32_MAX) {
		return false;
	}
	g->groups = groups;
	return ((ut64)g->inodes + g->inodes_per_group - 1) / g->inodes_per_group <= g->groups;
}

static bool ext2_group(Ext2Geometry *g, ut32 group, ut8 *desc) {
	ut8 *raw = malloc (g->descriptor_size);
	if (!raw) {
		return false;
	}
	bool ok = group < g->groups && ext2_disk (g, (ut64)(g->first + 1) * g->block_size
		+ (ut64)group * g->descriptor_size, raw, g->descriptor_size);
	if (ok && (g->ro_compat & (16 | 0x400))) {
		ut8 number[4];
		r_write_le32 (number, group);
		ut16 expected = r_read_le16 (raw + 30), actual;
		if (g->ro_compat & 0x400) {
			r_write_le16 (raw + 30, 0);
			ut32 crc = ext2_crc32c (g->checksum_seed, number, 4);
			actual = ext2_crc32c (crc, raw, g->descriptor_size);
		} else {
			ut16 crc = ext2_crc16 (UT16_MAX, g->uuid, 16);
			crc = ext2_crc16 (crc, number, 4);
			crc = ext2_crc16 (crc, raw, 30);
			actual = ext2_crc16 (crc, raw + 32, g->descriptor_size - 32);
		}
		r_write_le16 (raw + 30, expected);
		ok = actual == expected;
		if (!ok) {
			R_LOG_WARN ("Invalid ext4 group descriptor checksum for group %u", group);
		}
	}
	if (ok) {
		memset (desc, 0, 64);
		memcpy (desc, raw, R_MIN (g->descriptor_size, 64));
	}
	free (raw);
	return ok;
}

static ut64 ext2_group_block(Ext2Geometry *g, const ut8 *desc, unsigned offset) {
	return r_read_le32 (desc + offset) | (g->incompat & 128? (ut64)r_read_le32 (desc + offset + 32) << 32: 0);
}

static ut64 ext2_inode_offset(Ext2Geometry *g, ut64 id) {
	ut8 desc[64];
	if (!id || id > g->inodes || !ext2_group (g, (id - 1) / g->inodes_per_group, desc)) {
		return UT64_MAX;
	}
	ut64 table = ext2_group_block (g, desc, 8);
	ut64 relative = ((id - 1) % g->inodes_per_group) * g->inode_size;
	if (!table || table >= g->blocks || relative + g->inode_size > (g->blocks - table) * g->block_size) {
		return UT64_MAX;
	}
	return table * g->block_size + relative;
}

static ut32 ext2_inode_seed(Ext2Geometry *g, ut64 id, const ut8 *inode) {
	ut8 number[4];
	r_write_le32 (number, id);
	ut32 crc = ext2_crc32c (g->checksum_seed, number, 4);
	return ext2_crc32c (crc, inode + 100, 4);
}

static bool ext2_inode_valid(Ext2Geometry *g, ut64 id, ut8 *inode) {
	if (!(g->ro_compat & 0x400) || g->creator_os != 0 || !r_read_le16 (inode)) {
		return true;
	}
	bool high = g->inode_size >= 132 && r_read_le16 (inode + 128) >= 4;
	ut32 expected = r_read_le16 (inode + 124);
	if (high) {
		expected |= (ut32)r_read_le16 (inode + 130) << 16;
		r_write_le16 (inode + 130, 0);
	}
	r_write_le16 (inode + 124, 0);
	ut32 actual = ext2_crc32c (ext2_inode_seed (g, id, inode), inode, g->inode_size);
	r_write_le16 (inode + 124, expected);
	if (high) {
		r_write_le16 (inode + 130, expected >> 16);
	} else {
		actual &= UT16_MAX;
	}
	if (actual != expected) {
		R_LOG_WARN ("Invalid ext4 inode checksum for inode %"PFMT64u, id);
		return false;
	}
	return true;
}

static bool ext2_inode(Ext2Geometry *g, ut64 id, ut8 *inode) {
	ut64 offset = ext2_inode_offset (g, id);
	ut8 *raw = malloc (g->inode_size);
	if (!raw) {
		return false;
	}
	bool ok = offset != UT64_MAX && ext2_disk (g, offset, raw, g->inode_size) && ext2_inode_valid (g, id, raw);
	if (ok) {
		memcpy (inode, raw, 128);
	}
	free (raw);
	return ok;
}

static RBitset *ext2_metadata(Ext2Geometry *g);

static bool ext2_bitmap(Ext2Geometry *g, ut32 group, bool inode, ut8 *data) {
	ut8 desc[64];
	if (!ext2_group (g, group, desc)) {
		return false;
	}
	if ((g->ro_compat & (16 | 0x400)) && (r_read_le16 (desc + 18) & (inode? 1: 2))) {
		memset (data, 0, g->block_size);
		if (!inode) {
			RBitset *metadata = g->cache? g->cache->metadata: NULL;
			if (!metadata) {
				metadata = ext2_metadata (g);
			}
			if (!metadata) {
				return false;
			}
			ut64 first = g->first + (ut64)group * g->blocks_per_group;
			ut32 i, count = R_MIN ((ut64)g->blocks_per_group, g->blocks - first);
			for (i = 0; i < count; i++) {
				if (r_bitset_test (metadata, first + i)) {
					data[i / 8] |= 1 << (i % 8);
				}
			}
			if (g->cache) {
				g->cache->metadata = metadata;
			} else {
				r_bitset_free (metadata);
			}
		}
		return true;
	}
	ut64 block = ext2_group_block (g, desc, inode? 4: 0);
	if (!block || block >= g->blocks || !ext2_disk (g, block * g->block_size, data, g->block_size)) {
		return false;
	}
	if (g->ro_compat & 0x400) {
		ut32 expected = r_read_le16 (desc + (inode? 26: 24));
		ut32 actual = ext2_crc32c (g->checksum_seed, data, (inode? g->inodes_per_group: g->blocks_per_group) / 8);
		if (g->descriptor_size >= 64) {
			expected |= (ut32)r_read_le16 (desc + (inode? 58: 56)) << 16;
		} else {
			actual &= UT16_MAX;
		}
		if (actual != expected) {
			R_LOG_WARN ("Invalid ext4 %s bitmap checksum for group %u", inode? "inode": "block", group);
			return false;
		}
	}
	return true;
}

static int ext2_allocated(Ext2Geometry *g, ut64 number, bool inode) {
	ut64 index = inode? number - 1: number - g->first;
	ut32 per_group = inode? g->inodes_per_group: g->blocks_per_group;
	if ((inode && (!number || number > g->inodes)) || (!inode && (number < g->first || number >= g->blocks))) {
		return -1;
	}
	ut32 group = index / per_group;
	Ext2BitmapCache *cache = g->cache;
	ut8 *data = cache? cache->data: NULL;
	if (!data) {
		data = malloc (g->block_size);
	}
	if (!data) {
		return -1;
	}
	bool known = cache && cache->valid && cache->group == group && cache->inode == inode;
	if (!known) {
		known = ext2_bitmap (g, group, inode, data);
	}
	int result = known? (data[(index % per_group) / 8] >> (index % per_group % 8)) & 1: -1;
	if (cache) {
		cache->data = data;
		cache->valid = known;
		cache->group = group;
		cache->inode = inode;
	} else {
		free (data);
	}
	return result;
}

static ut64 ext2_size(const ut8 *inode) {
	ut64 size = r_read_le32 (inode + 4);
	if ((r_read_le16 (inode) & 0xf000) == 0x8000 || ((r_read_le16 (inode) & 0xf000) == 0x4000 && (r_read_le32 (inode + 32) & 0x80000))) {
		size |= (ut64)r_read_le32 (inode + 108) << 32;
	}
	return size;
}

static ut64 ext2_acl(Ext2Geometry *g, const ut8 *inode) {
	return r_read_le32 (inode + 104) | (g->creator_os == 0 && (g->incompat & 128)? (ut64)r_read_le16 (inode + 118) << 32: 0);
}

static bool ext2_inline_link(Ext2Geometry *g, const ut8 *inode) {
	return (r_read_le16 (inode) & 0xf000) == 0xa000 && ext2_size (inode) <= 60
		&& r_read_le32 (inode + 28) <= (ext2_acl (g, inode)? g->block_size / 512: 0);
}

static bool ext2_extent_node(Ext2Geometry *g, const ut8 *data, ut32 length, unsigned depth, ut64 lower, ut64 upper, ut32 seed, bool external) {
	ut32 entries = r_read_le16 (data + 2), maximum = r_read_le16 (data + 4);
	if (r_read_le16 (data) != 0xf30a || depth > 5 || r_read_le16 (data + 6) != depth
			|| maximum > (length - 12) / 12 || !maximum || entries > maximum || (depth && !entries)) {
		return false;
	}
	if (external && (g->ro_compat & 0x400)) {
		ut32 tail = 12 + maximum * 12;
		if (tail > length - 4 || ext2_crc32c (seed, data, tail) != r_read_le32 (data + tail)) {
			R_LOG_WARN ("Invalid ext4 extent block checksum");
			return false;
		}
	}
	ut64 previous = lower;
	unsigned i;
	for (i = 0; i < entries; i++) {
		const ut8 *record = data + 12 + i * 12;
		ut64 logical = r_read_le32 (record);
		ut32 count = r_read_le16 (record + 4);
		if (logical < previous || logical >= upper || (depth && i && logical == previous)) {
			return false;
		}
		if (depth) {
			ut64 block = r_read_le32 (record + 4) | (ut64)r_read_le16 (record + 8) << 32;
			if (!block || block < g->first || block >= g->blocks) {
				return false;
			}
			previous = logical;
		} else {
			count = count > 32768? count - 32768: count;
			ut64 block = r_read_le32 (record + 8) | (ut64)r_read_le16 (record + 6) << 32;
			if (!count || !block || block < g->first || block >= g->blocks || count > g->blocks - block || count > upper - logical) {
				return false;
			}
			previous = logical + count;
		}
	}
	return true;
}

static bool ext2_extent_lookup(Ext2Geometry *g, const ut8 *inode, ut64 id, ut64 logical, RBitset *owners, ut64 *block, bool *unwritten) {
	const ut8 *node = inode + 40;
	ut8 *buffer = NULL;
	ut64 lower = 0, upper = (ut64)UT32_MAX + 1, seen[5];
	unsigned depth = r_read_le16 (node + 6), level = 0;
	ut32 seed = ext2_inode_seed (g, id, inode);
	bool ok = false;
	*block = 0;
	*unwritten = false;
	while (logical < upper && ext2_extent_node (g, node, level? g->block_size: 60, depth, lower, upper, seed, level != 0)) {
		unsigned i, entries = r_read_le16 (node + 2);
		const ut8 *record = NULL;
		for (i = 0; i < entries; i++) {
			const ut8 *candidate = node + 12 + i * 12;
			if (r_read_le32 (candidate) > logical) {
				upper = r_read_le32 (candidate);
				break;
			}
			record = candidate;
		}
		if (!record) {
			ok = true;
			break;
		}
		lower = r_read_le32 (record);
		if (!depth) {
			ut32 count = r_read_le16 (record + 4);
			*unwritten = count > 32768;
			count = *unwritten? count - 32768: count;
			if (logical - lower < count) {
				*block = (r_read_le32 (record + 8) | (ut64)r_read_le16 (record + 6) << 32) + logical - lower;
			}
			ok = true;
			break;
		}
		ut64 child = r_read_le32 (record + 4) | (ut64)r_read_le16 (record + 8) << 32;
		if (owners && (ext2_allocated (g, child, false) != 0 || r_bitset_test (owners, child))) {
			break;
		}
		for (i = 0; i < level && seen[i] != child; i++) {
		}
		if (i != level) {
			break;
		}
		seen[level++] = child;
		if (!buffer) {
			buffer = malloc (g->block_size);
			if (!buffer) {
				break;
			}
		}
		if (!ext2_disk (g, child * g->block_size, buffer, g->block_size)) {
			break;
		}
		node = buffer;
		depth--;
	}
	free (buffer);
	return ok;
}

// Resolve one classic block map, stopping on cycles and invalid pointers.
static bool ext2_block(Ext2Geometry *g, const ut8 *inode, ut64 id, ut64 logical, RBitset *owners, ut64 *block) {
	ut64 count = g->block_size / 4, span = count;
	ut32 level, depth;
	ut64 seen[3];
	if (r_read_le32 (inode + 32) & 0x10000000) {
		return false;
	}
	if (r_read_le32 (inode + 32) & 0x80000) {
		bool unwritten;
		return ext2_extent_lookup (g, inode, id, logical, owners, block, &unwritten) && !unwritten;
	}
	if (logical < 12) {
		*block = r_read_le32 (inode + 40 + logical * 4);
		return !*block || (*block >= g->first && *block < g->blocks);
	}
	logical -= 12;
	for (depth = 1; depth <= 3 && logical >= span; depth++) {
		logical -= span;
		span *= count;
	}
	if (depth > 3) {
		return false;
	}
	*block = r_read_le32 (inode + 40 + (11 + depth) * 4);
	for (level = 0; level < depth && *block; level++) {
		ut32 j;
		for (j = 0; j < level; j++) {
			if (seen[j] == *block) {
				return false;
			}
		}
		seen[level] = *block;
		if (*block < g->first || *block >= g->blocks || (owners && (ext2_allocated (g, *block, false) != 0 || r_bitset_test (owners, *block)))) {
			return false;
		}
		span /= count;
		ut8 raw[4];
		if (!ext2_disk (g, (ut64)*block * g->block_size + (logical / span) * 4, raw, 4)) {
			return false;
		}
		*block = r_read_le32 (raw);
		logical %= span;
	}
	ut32 i;
	for (i = 0; i < level; i++) {
		if (*block && seen[i] == *block) {
			return false;
		}
	}
	return !*block || (*block >= g->first && *block < g->blocks);
}

static bool ext2_file_block(Ext2Geometry *g, Ext2File *entry, ut64 id, ut64 logical, ut64 *block, bool *unwritten) {
	*unwritten = false;
	if (!entry->contiguous) {
		if (r_read_le32 (entry->inode + 32) & 0x80000) {
			return ext2_extent_lookup (g, entry->inode, id, logical, entry->owners, block, unwritten);
		}
		return ext2_block (g, entry->inode, id, logical, entry->owners, block);
	}
	ut64 first;
	if (!ext2_block (g, entry->inode, id, 0, entry->owners, &first)
			|| !first || first >= g->blocks || logical >= g->blocks - first) {
		return false;
	}
	*block = first + logical;
	return true;
}

static void ext2_fill(Ext2Geometry *g, RFSFile *file, const ut8 *inode, ut64 id) {
	file->id = id;
	file->size = ext2_size (inode);
	file->perm = r_read_le16 (inode) & 07777;
	file->uid = r_read_le16 (inode + 2);
	file->gid = r_read_le16 (inode + 24);
	if (g->creator_os <= 1) {
		file->uid |= (ut32)r_read_le16 (inode + 120) << 16;
		file->gid |= (ut32)r_read_le16 (inode + 122) << 16;
	}
	file->time = r_read_le32 (inode + 16);
	ut16 mode = r_read_le16 (inode) & 0xf000;
	file->type = mode == 0x4000? 'd': mode == 0x8000? 'f': mode == 0xa000? 'l': 's';
}

typedef int (*Ext2BlockCb)(ut64 block, ut64 logical, ut64 size, unsigned depth, ut32 flags, void *user);

typedef struct {
	Ext2Geometry *g;
	Ext2BlockCb cb;
	void *user;
	RBitset *visited;
} Ext2Walk;

static int ext2_walk_tree(Ext2Walk *walk, ut64 block, unsigned depth, ut64 logical, ut64 span, ut64 size) {
	Ext2Geometry *g = walk->g;
	if (block && (block < g->first || block >= g->blocks)) {
		return R_FS_WALK_ERROR;
	}
	if (block && !r_bitset_set (walk->visited, block)) {
		return R_FS_WALK_ERROR;
	}
	if (!block || !depth) {
		return walk->cb (block, logical, size, 0, 0, walk->user);
	}
	int status = walk->cb (block, logical, g->block_size, depth, 0, walk->user);
	if (status != R_FS_WALK_COMPLETE) {
		return status;
	}
	ut8 *data = malloc (g->block_size);
	if (!data) {
		return R_FS_WALK_ERROR;
	}
	if (!ext2_disk (g, (ut64)block * g->block_size, data, g->block_size)) {
		free (data);
		return R_FS_WALK_ERROR;
	}
	unsigned i;
	ut64 child_span = span / (g->block_size / 4), offset;
	for (offset = 0, i = 0; offset < size; offset += child_span, i++) {
		status = ext2_walk_tree (walk, r_read_le32 (data + i * 4), depth - 1,
			logical + offset, child_span, R_MIN (child_span, size - offset));
		if (status != R_FS_WALK_COMPLETE) {
			break;
		}
	}
	free (data);
	return status;
}

static int ext2_walk_extents(Ext2Walk *walk, const ut8 *node, unsigned depth, ut64 lower, ut64 upper, ut64 size, ut32 seed, bool external) {
	Ext2Geometry *g = walk->g;
	if (!ext2_extent_node (g, node, external? g->block_size: 60, depth, lower, upper, seed, external)) {
		return R_FS_WALK_ERROR;
	}
	ut64 position = lower * g->block_size;
	unsigned i, entries = r_read_le16 (node + 2);
	int status = R_FS_WALK_COMPLETE;
	for (i = 0; i < entries && position < size; i++) {
		const ut8 *record = node + 12 + i * 12;
		ut64 logical = (ut64)r_read_le32 (record) * g->block_size;
		if (logical > position) {
			status = walk->cb (0, position, R_MIN (logical, size) - position, 0, 0, walk->user);
			if (status != R_FS_WALK_COMPLETE || logical >= size) {
				return status;
			}
		}
		if (depth) {
			ut64 block = r_read_le32 (record + 4) | (ut64)r_read_le16 (record + 8) << 32;
			if (!r_bitset_set (walk->visited, block)) {
				return R_FS_WALK_ERROR;
			}
			status = walk->cb (block, logical, g->block_size, depth, 0, walk->user);
			if (status != R_FS_WALK_COMPLETE) {
				return status;
			}
			ut8 *data = malloc (g->block_size);
			if (!data) {
				return R_FS_WALK_ERROR;
			}
			ut64 end = i + 1 < entries? r_read_le32 (record + 12): upper;
			if (!ext2_disk (g, block * g->block_size, data, g->block_size)) {
				free (data);
				return R_FS_WALK_ERROR;
			}
			status = ext2_walk_extents (walk, data, depth - 1, logical / g->block_size, end, R_MIN (size, end * g->block_size), seed, true);
			free (data);
			position = end * g->block_size;
		} else {
			ut32 count = r_read_le16 (record + 4);
			ut32 flags = count > 32768? R_FS_RANGE_UNWRITTEN: 0;
			count = flags? count - 32768: count;
			ut64 block = r_read_le32 (record + 8) | (ut64)r_read_le16 (record + 6) << 32;
			ut32 j;
			for (j = 0; j < count && logical < size; j++, logical += g->block_size) {
				if (!r_bitset_set (walk->visited, block + j)) {
					return R_FS_WALK_ERROR;
				}
				status = walk->cb (block + j, logical, R_MIN ((ut64)g->block_size, size - logical), 0, flags, walk->user);
				if (status != R_FS_WALK_COMPLETE) {
					return status;
				}
			}
			position = logical;
		}
		if (status != R_FS_WALK_COMPLETE) {
			return status;
		}
	}
	return position < size? walk->cb (0, position, size - position, 0, 0, walk->user): R_FS_WALK_COMPLETE;
}

static int ext2_walk_inode(Ext2Geometry *g, const ut8 *inode, ut64 id, ut64 size, Ext2BlockCb cb, void *user) {
	if (r_read_le32 (inode + 32) & 0x10000000) {
		return R_FS_WALK_UNSUPPORTED;
	}
	Ext2Walk walk = { .g = g, .cb = cb, .user = user, .visited = r_bitset_new () };
	if (!walk.visited) {
		return R_FS_WALK_ERROR;
	}
	if (r_read_le32 (inode + 32) & 0x80000) {
		ut64 capacity = ((ut64)UT32_MAX + 1) * g->block_size;
		int status = size > capacity? R_FS_WALK_ERROR: ext2_walk_extents (&walk, inode + 40,
			r_read_le16 (inode + 46), 0, (ut64)UT32_MAX + 1, size, ext2_inode_seed (g, id, inode), false);
		r_bitset_free (walk.visited);
		return status;
	}
	ut64 logical = 0, span = g->block_size;
	unsigned i;
	for (i = 0; i < 15 && logical < size; i++) {
		unsigned depth = i < 12? 0: i - 11;
		if (depth) {
			span *= g->block_size / 4;
		}
		int status = ext2_walk_tree (&walk, r_read_le32 (inode + 40 + i * 4), depth,
			logical, span, R_MIN (span, size - logical));
		if (status != R_FS_WALK_COMPLETE) {
			r_bitset_free (walk.visited);
			return status;
		}
		logical += R_MIN (span, size - logical);
	}
	r_bitset_free (walk.visited);
	return logical == size? R_FS_WALK_COMPLETE: R_FS_WALK_ERROR;
}

static ut64 ext2_capacity(Ext2Geometry *g, const ut8 *inode) {
	if (r_read_le32 (inode + 32) & 0x80000) {
		return ((ut64)UT32_MAX + 1) * g->block_size;
	}
	ut64 span = g->block_size, capacity = 12 * span;
	unsigned depth;
	for (depth = 0; depth < 3; depth++) {
		span *= g->block_size / 4;
		capacity += span;
	}
	return capacity;
}

static int ext2_owner_block(ut64 block, ut64 logical, ut64 size, unsigned depth, ut32 flags, void *user) {
	return !block || r_bitset_test (user, block) || r_bitset_set (user, block)? R_FS_WALK_COMPLETE: R_FS_WALK_ERROR;
}

static bool ext2_super_group(ut32 group, bool sparse) {
	if (!sparse || group <= 1) {
		return true;
	}
	ut32 bases[] = { 3, 5, 7 };
	unsigned i;
	for (i = 0; i < R_ARRAY_SIZE (bases); i++) {
		ut32 number = group;
		while (!(number % bases[i])) {
			number /= bases[i];
		}
		if (number == 1) {
			return true;
		}
	}
	return false;
}

typedef bool (*Ext2InodeCb)(Ext2Geometry *g, ut32 id, const ut8 *inode, bool allocated, void *user);

static bool ext2_scan_inodes(Ext2Geometry *g, Ext2InodeCb cb, void *user) {
	ut8 *bitmap = malloc (g->block_size), *data = malloc (g->block_size);
	if (!bitmap || !data) {
		free (bitmap);
		free (data);
		return false;
	}
	ut32 group;
	bool ok = true;
	for (group = 0; group < g->groups && (ut64)group * g->inodes_per_group < g->inodes; group++) {
		ut8 desc[64];
		if (!ext2_group (g, group, desc)) {
			ok = false;
			continue;
		}
		if ((g->ro_compat & (16 | 0x400)) && (r_read_le16 (desc + 18) & 1)) {
			continue;
		}
		ut64 table = ext2_group_block (g, desc, 8);
		ut64 table_blocks = ((ut64)g->inodes_per_group * g->inode_size + g->block_size - 1) / g->block_size;
		if (!table || table >= g->blocks || table_blocks > g->blocks - table || !ext2_bitmap (g, group, true, bitmap)) {
			ok = false;
			continue;
		}
		ut64 first = (ut64)group * g->inodes_per_group;
		ut32 i, count = R_MIN ((ut64)g->inodes_per_group, g->inodes - first);
		ut32 per_block = g->block_size / g->inode_size;
		for (i = 0; i < count; i++) {
			if (!(i % per_block) && !ext2_disk (g, (ut64)table * g->block_size + (ut64)i * g->inode_size, data, g->block_size)) {
				ok = false;
				break;
			}
			ut8 *inode = data + (i % per_block) * g->inode_size;
			if (!ext2_inode_valid (g, first + i + 1, inode)) {
				ok = false;
				continue;
			}
			if (!cb (g, first + i + 1, inode,
					(bitmap[i / 8] >> (i % 8)) & 1, user)) {
				ok = false;
				goto done;
			}
		}
	}
 done:
	free (bitmap);
	free (data);
	return ok;
}

static bool ext2_owner_inode(Ext2Geometry *g, ut32 id, const ut8 *inode, bool allocated, void *user) {
	if (id >= g->first_inode && !allocated && r_read_le32 (inode + 20)) {
		return true;
	}
	ut64 capacity = ext2_capacity (g, inode);
	ut16 mode = r_read_le16 (inode) & 0xf000;
	ut64 acl = ext2_acl (g, inode);
	bool inline_link = ext2_inline_link (g, inode);
	if (!inline_link && (mode == 0x8000 || mode == 0x4000 || mode == 0xa000 || id < g->first_inode)
			&& ext2_walk_inode (g, inode, id, capacity, ext2_owner_block, user) != R_FS_WALK_COMPLETE) {
		return false;
	}
	if (acl) {
		if (acl >= g->blocks || acl < g->first) {
			return false;
		}
		if (!r_bitset_test (user, acl) && !r_bitset_set (user, acl)) {
			return false;
		}
	}
	return true;
}

static RBitset *ext2_metadata(Ext2Geometry *g) {
	RBitset *used = r_bitset_new ();
	if (!used) {
		return NULL;
	}
	ut32 group;
	for (group = 0; group < g->groups; group++) {
		ut8 desc[64];
		if (!ext2_group (g, group, desc)) {
			goto failure;
		}
		ut64 bitmap = ext2_group_block (g, desc, 0), inodes = ext2_group_block (g, desc, 4), table = ext2_group_block (g, desc, 8);
		ut64 count = ((ut64)g->inodes_per_group * g->inode_size + g->block_size - 1) / g->block_size;
		if (!bitmap || bitmap >= g->blocks || !inodes || inodes >= g->blocks || !table || table >= g->blocks
				|| count > g->blocks - table) {
			goto failure;
		}
		if ((!r_bitset_test (used, bitmap) && !r_bitset_set (used, bitmap))
				|| (!r_bitset_test (used, inodes) && !r_bitset_set (used, inodes))) {
			goto failure;
		}
		ut64 block;
		for (block = table; block < table + count; block++) {
			if (!r_bitset_test (used, block) && !r_bitset_set (used, block)) {
				goto failure;
			}
		}
		if (ext2_super_group (group, g->ro_compat & 1)) {
			ut64 first = g->first + (ut64)group * g->blocks_per_group;
			ut64 reserved = 1 + ((ut64)g->groups * g->descriptor_size + g->block_size - 1) / g->block_size + g->reserved_gdt;
			if (reserved > g->blocks - first) {
				goto failure;
			}
			for (block = first; block < first + reserved; block++) {
				if (!r_bitset_test (used, block) && !r_bitset_set (used, block)) {
					goto failure;
				}
			}
		}
	}
	return used;
 failure:
	r_bitset_free (used);
	return NULL;
}

static RBitset *ext2_owners(Ext2Geometry *g) {
	RBitset *used = ext2_metadata (g);
	if (used && !ext2_scan_inodes (g, ext2_owner_inode, used)) {
		r_bitset_free (used);
		return NULL;
	}
	return used;
}

static int ext2_count_block(ut64 block, ut64 logical, ut64 size, unsigned depth, ut32 flags, void *user) {
	if (block) {
		(*(ut64 *)user)++;
	}
	return R_FS_WALK_COMPLETE;
}

static bool ext2_recovery_owners(Ext2Geometry *g, Ext2File *entry, ut64 id) {
	if (!entry->recovery) {
		return true;
	}
	if (!entry->checked) {
		entry->owners = ext2_owners (g);
		entry->checked = true;
		ut64 blocks = ext2_acl (g, entry->inode)? 1: 0;
		ut64 stored = r_read_le32 (entry->inode + 28);
		if (g->ro_compat & 8) {
			stored |= (ut64)r_read_le16 (entry->inode + 116) << 32;
		}
		ut32 units = (g->ro_compat & 8) && (r_read_le32 (entry->inode + 32) & 0x40000)? 1: g->block_size / 512;
		int status = ext2_walk_inode (g, entry->inode, id, ext2_capacity (g, entry->inode), ext2_count_block, &blocks);
		entry->sparse_known = status == R_FS_WALK_COMPLETE
			&& blocks <= UT64_MAX / units && blocks * units == stored;
	}
	return entry->owners != NULL;
}

typedef struct {
	Ext2Geometry *g;
	RFSFile *file;
	RFSRangeCb cb;
	void *user;
	RFSRange run;
	ut64 readable;
} Ext2Extents;

static int ext2_extent_block(ut64 block, ut64 logical, ut64 size, unsigned depth, ut32 flags, void *user) {
	Ext2Extents *output = user;
	Ext2File *entry = output->file->ptr;
	if (!block && entry->recovery && !entry->sparse_known && !entry->contiguous) {
		return R_FS_WALK_ERROR;
	}
	int allocated = block? ext2_allocated (output->g, block, false): 0;
	if (allocated < 0 || (entry->recovery && block && (allocated || r_bitset_test (entry->owners, block)))) {
		if (allocated > 0 || (block && entry->owners && r_bitset_test (entry->owners, block))) {
			output->file->flags |= R_FS_FILE_CONFLICT;
		}
		return R_FS_WALK_ERROR;
	}
	if (depth) {
		return R_FS_WALK_COMPLETE;
	}
	flags |= !block? R_FS_RANGE_SPARSE: allocated? R_FS_RANGE_ALLOCATED: R_FS_RANGE_FREE;
	if (entry->contiguous || (!block && entry->recovery)) {
		output->file->flags |= R_FS_FILE_HEURISTIC;
		flags |= R_FS_RANGE_HEURISTIC;
	}
	ut64 physical = block? output->file->root->delta + (ut64)block * output->g->block_size: UT64_MAX;
	RFSRange *run = &output->run;
	if (run->size && (run->flags != flags || (block && run->physical + run->size != physical))) {
		if (!output->cb (run, output->user)) {
			return R_FS_WALK_STOPPED;
		}
		run->size = 0;
	}
	if (!run->size) {
		run->logical = logical;
		run->physical = physical;
		run->flags = flags;
	}
	run->size += size;
	output->readable = logical + size;
	return R_FS_WALK_COMPLETE;
}

static int FSP(_forensic_extents)(RFSFile *file, RFSRangeCb cb, void *user) {
	Ext2Geometry g;
	Ext2File *entry = file->ptr;
	if (!ext2_geometry (file->root, &g) || file->id == UT64_MAX || (file->type != 'f' && file->type != 'd' && file->type != 'l')) {
		return R_FS_WALK_UNSUPPORTED;
	}
	g.cache = &entry->bitmap;
	if (ext2_inline_link (&g, entry->inode)) {
		ut64 offset = ext2_inode_offset (&g, file->id);
		if (offset == UT64_MAX) {
			return R_FS_WALK_ERROR;
		}
		RFSRange range = { 0, file->root->delta + offset + 40, file->size, R_FS_RANGE_ALLOCATED };
		return !range.size || cb (&range, user)? R_FS_WALK_COMPLETE: R_FS_WALK_STOPPED;
	}
	if (!ext2_recovery_owners (&g, entry, file->id)) {
		file->flags |= R_FS_FILE_PARTIAL;
		return R_FS_WALK_ERROR;
	}
	Ext2Extents output = { .g = &g, .file = file, .cb = cb, .user = user };
	int status = R_FS_WALK_COMPLETE;
	if (entry->contiguous) {
		ut64 offset;
		for (offset = 0; offset < file->size; offset += g.block_size) {
			ut64 block;
			bool unwritten;
			if (!ext2_file_block (&g, entry, file->id, offset / g.block_size, &block, &unwritten)) {
				status = R_FS_WALK_ERROR;
				break;
			}
			status = ext2_extent_block (block, offset, R_MIN ((ut64)g.block_size, file->size - offset), 0, 0, &output);
			if (status != R_FS_WALK_COMPLETE) {
				break;
			}
		}
	} else {
		status = ext2_walk_inode (&g, entry->inode, file->id, file->size, ext2_extent_block, &output);
	}
	if (output.run.size && status != R_FS_WALK_STOPPED && !cb (&output.run, user)) {
		return R_FS_WALK_STOPPED;
	}
	if (entry->recovery && status != R_FS_WALK_STOPPED) {
		entry->readable = output.readable;
		entry->planned = true;
	}
	if (status == R_FS_WALK_ERROR) {
		file->flags |= R_FS_FILE_PARTIAL;
	}
	return status;
}

static RFSFile *FSP(_forensic_open_id)(RFSRoot *root, ut64 id, ut32 flags) {
	Ext2Geometry g;
	ut8 inode[128];
	if ((flags & ~(R_FS_OPEN_RECOVER | R_FS_OPEN_CONTIGUOUS)) || !ext2_geometry (root, &g) || !ext2_inode (&g, id, inode)
			|| !(r_read_le16 (inode) & 0xf000)) {
		return NULL;
	}
	int allocated = ext2_allocated (&g, id, true);
	if (allocated < 0 || ((flags & (R_FS_OPEN_RECOVER | R_FS_OPEN_CONTIGUOUS)) && (allocated || !r_read_le32 (inode + 20)))) {
		return NULL;
	}
	char *name = r_str_newf ("inode-%"PFMT64u, id);
	RFSFile *file = r_fs_file_new (root, name);
	free (name);
	Ext2File *entry = R_NEW0 (Ext2File);
	memcpy (entry->inode, inode, sizeof (inode));
	entry->recovery = flags & (R_FS_OPEN_RECOVER | R_FS_OPEN_CONTIGUOUS);
	entry->contiguous = flags & R_FS_OPEN_CONTIGUOUS;
	file->ptr = entry;
	ext2_fill (&g, file, inode, id);
	if (entry->contiguous) {
		ut64 block;
		bool unwritten;
		if (file->type != 'f' || !ext2_file_block (&g, entry, id, 0, &block, &unwritten)) {
			free (entry);
			r_fs_file_free (file);
			return NULL;
		}
		file->flags |= R_FS_FILE_HEURISTIC;
	}
	if (!allocated) {
		file->flags |= R_FS_FILE_DELETED;
	}
	ut64 block;
	if (ext2_inline_link (&g, inode)) {
		ut64 offset = ext2_inode_offset (&g, id);
		if (offset != UT64_MAX) {
			file->off = root->delta + offset + 40;
		}
	} else if (file->size && ext2_block (&g, inode, id, 0, NULL, &block) && block) {
		file->off = root->delta + (ut64)block * g.block_size;
	}
	return file;
}

static bool ext2_accept_range(const RFSRange *range, void *user) {
	return true;
}

static int FSP(_forensic_read)(RFSFile *file, ut64 addr, int len) {
	Ext2File *entry = file->ptr;
	if (entry->grub) {
		file->ptr = entry->grub;
		int result = FSP(_read) (file, addr, len);
		file->ptr = entry;
		return result;
	}
	Ext2Geometry g;
	if (!ext2_geometry (file->root, &g) || (file->type != 'f' && file->type != 'l')) {
		return -1;
	}
	if (addr >= file->size) {
		return 0;
	}
	g.cache = &entry->bitmap;
	if (ext2_inline_link (&g, entry->inode)) {
		len = R_MIN ((ut64)len, file->size - addr);
		memcpy (file->data, entry->inode + 40 + addr, len);
		return len;
	}
	if (!ext2_recovery_owners (&g, entry, file->id)) {
		file->flags |= R_FS_FILE_PARTIAL;
		return -1;
	}
	ut64 readable = file->size;
	if (entry->recovery) {
		if (!entry->planned) {
			FSP(_forensic_extents) (file, ext2_accept_range, NULL);
		}
		if (!entry->planned || addr >= entry->readable) {
			return -1;
		}
		readable = entry->readable;
	}
	len = R_MIN ((ut64)len, readable - addr);
	int done = 0;
	while (done < len) {
		ut64 block;
		bool unwritten;
		ut64 off = addr + done;
		if (!ext2_file_block (&g, entry, file->id, off / g.block_size, &block, &unwritten)
				|| (entry->recovery && !block && !entry->sparse_known)
				|| (entry->recovery && block && (ext2_allocated (&g, block, false) != 0 || r_bitset_test (entry->owners, block)))) {
			file->flags |= R_FS_FILE_PARTIAL | R_FS_FILE_CONFLICT;
			break;
		}
		int chunk = R_MIN (len - done, g.block_size - off % g.block_size);
		if (block && !unwritten) {
			if (!ext2_disk (&g, (ut64)block * g.block_size + off % g.block_size, file->data + done, chunk)) {
				file->flags |= R_FS_FILE_PARTIAL;
				break;
			}
		} else {
			memset (file->data + done, 0, chunk);
		}
		done += chunk;
	}
	return done? done: -1;
}

static void FSP(_forensic_close)(RFSFile *file) {
	Ext2File *entry = file->ptr;
	if (entry->grub) {
		file->ptr = entry->grub;
		FSP(_close) (file);
		grubfs_free (entry->grub);
	}
	free (entry->bitmap.data);
	r_bitset_free (entry->bitmap.metadata);
	r_bitset_free (entry->owners);
	free (entry);
	file->ptr = NULL;
}

typedef bool (*Ext2DirCb)(ut32 id, const char *name, bool deleted, void *user);

static bool ext2_entries(Ext2Geometry *g, const ut8 *inode, ut64 id, Ext2DirCb cb, void *user, bool slack) {
	if ((r_read_le16 (inode) & 0xf000) != 0x4000) {
		return false;
	}
	ut8 *buf = malloc (g->block_size);
	if (!buf) {
		return false;
	}
	ut64 offset, original_size = ext2_size (inode);
	ut64 size = R_MIN (original_size, (ut64)g->blocks * g->block_size);
	bool ok = original_size == size;
	for (offset = 0; offset < size; offset += g->block_size) {
		ut64 block;
		if (!ext2_block (g, inode, id, offset / g->block_size, NULL, &block) || !block
				|| !ext2_disk (g, (ut64)block * g->block_size, buf, g->block_size)) {
			ok = false;
			break;
		}
		ut32 pos = 0, end = R_MIN ((ut64)g->block_size, size - offset), next = 0;
		bool index = (r_read_le32 (inode + 32) & 0x1000) && (!offset || !r_read_le32 (buf));
		if ((g->ro_compat & 0x400) && !index && end == g->block_size) {
			const ut8 *tail = buf + end - 12;
			if (r_read_le32 (tail) || r_read_le16 (tail + 4) != 12 || tail[6] || tail[7] != 0xde
					|| ext2_crc32c (ext2_inode_seed (g, id, inode), buf, end - 12) != r_read_le32 (tail + 8)) {
				R_LOG_WARN ("Invalid ext4 directory checksum: retaining readable entries");
			} else {
				end -= 12;
			}
		}
		while (pos + 8 <= end) {
			bool deleted = pos < next;
			ut32 id = r_read_le32 (buf + pos);
			ut32 length = r_read_le16 (buf + pos + 4);
			if (length == 65535 && g->block_size == 65536) {
				length = 65536;
			}
			ut32 namesize = g->incompat & 2? buf[pos + 6]: r_read_le16 (buf + pos + 6);
			ut32 limit = deleted? next: end;
			bool valid = length >= 8 && !(length & 3) && length <= limit - pos
				&& namesize && namesize <= 255 && namesize <= length - 8
				&& id && id <= g->inodes && !memchr (buf + pos + 8, 0, namesize)
				&& !memchr (buf + pos + 8, '/', namesize);
			if (valid) {
				char name[256];
				memcpy (name, buf + pos + 8, namesize);
				name[namesize] = 0;
				if (!cb (id, name, deleted, user)) {
					free (buf);
					return true;
				}
			}
			if (!deleted) {
				if (length < 8 || (length & 3) || length > end - pos) {
					ok = false;
					if (!slack) {
						break;
					}
					next = end;
				} else {
					next = pos + length;
				}
			}
			if (slack && !index) {
				pos += valid? (8 + namesize + 3) & ~3U: 4;
			} else {
				pos = next;
			}
		}
	}
	free (buf);
	if (!ok) {
		R_LOG_WARN ("Damaged ext2 directory: retaining readable entries");
	}
	return ok;
}

typedef struct {
	const char *name;
	ut32 id;
} Ext2Lookup;

static bool ext2_lookup_cb(ut32 id, const char *name, bool deleted, void *user) {
	Ext2Lookup *lookup = user;
	if (!deleted && !strcmp (name, lookup->name)) {
		lookup->id = id;
		return false;
	}
	return true;
}

static ut32 ext2_lookup_at(Ext2Geometry *g, const char *path, ut32 id, unsigned links) {
	if (links > 40) {
		return 0;
	}
	ut8 inode[128];
	char *copy = strdup (path), *state = NULL;
	char *part = r_str_tok_r (copy, "/", &state);
	while (part) {
		ut32 parent = id;
		Ext2Lookup lookup = { part, 0 };
		if (!ext2_inode (g, id, inode)) {
			id = 0;
			break;
		}
		ext2_entries (g, inode, id, ext2_lookup_cb, &lookup, false);
		id = lookup.id;
		if (!id || !ext2_inode (g, id, inode)) {
			id = 0;
			break;
		}
		if ((r_read_le16 (inode) & 0xf000) == 0xa000) {
			ut64 size = ext2_size (inode);
			if (!size || size > 4096) {
				id = 0;
				break;
			}
			char *target = malloc (size + 1);
			if (!target) {
				id = 0;
				break;
			}
			if (ext2_inline_link (g, inode)) {
				memcpy (target, inode + 40, size);
			} else {
				ut64 offset;
				for (offset = 0; offset < size; offset += g->block_size) {
					ut64 block;
					int chunk = R_MIN ((ut64)g->block_size, size - offset);
					if (!ext2_block (g, inode, id, offset / g->block_size, NULL, &block) || !block
							|| !ext2_disk (g, (ut64)block * g->block_size, (ut8 *)target + offset, chunk)) {
						id = 0;
						break;
					}
				}
			}
			target[size] = 0;
			char *remaining = id && !memchr (target, 0, size)? r_str_newf ("%s/%s", target, state? state: ""): NULL;
			id = remaining? ext2_lookup_at (g, remaining, *target == '/'? 2: parent, links + 1): 0;
			free (remaining);
			free (target);
			break;
		}
		part = r_str_tok_r (NULL, "/", &state);
	}
	free (copy);
	return id;
}

static ut32 ext2_lookup(Ext2Geometry *g, const char *path) {
	return ext2_lookup_at (g, path, 2, 0);
}

static RFSFile *FSP(_forensic_open)(RFSRoot *root, const char *path, bool create) {
	RFSFile *file = FSP(_open) (root, path, create);
	if (!file) {
		Ext2Geometry g;
		ut8 inode[128];
		ut32 id = ext2_geometry (root, &g)? ext2_lookup (&g, path): 0;
		return !create && id && ext2_inode (&g, id, inode) && (r_read_le16 (inode) & 0xf000) == 0x8000?
			FSP(_forensic_open_id) (root, id, 0): NULL;
	}
	Ext2File *entry = R_NEW0 (Ext2File);
	entry->grub = file->ptr;
	file->ptr = entry;
	Ext2Geometry g;
	if (ext2_geometry (root, &g)) {
		ut32 id = ext2_lookup (&g, path);
		if (id && ext2_inode (&g, id, entry->inode) && (r_read_le16 (entry->inode) & 0xf000) == 0x8000) {
			ext2_fill (&g, file, entry->inode, id);
			ut64 block;
			file->off = ext2_block (&g, entry->inode, id, 0, NULL, &block) && block?
				root->delta + (ut64)block * g.block_size: UT64_MAX;
		}
	}
	return file;
}

typedef struct {
	Ext2Geometry *g;
	RList *list;
	int view;
} Ext2Directory;

static bool ext2_directory_cb(ut32 id, const char *name, bool deleted, void *user) {
	Ext2Directory *dir = user;
	if (!(dir->view & (deleted? R_FS_VIEW_DELETED: R_FS_VIEW_NORMAL))) {
		return true;
	}
	ut8 inode[128];
	if (!ext2_inode (dir->g, id, inode) || !(r_read_le16 (inode) & 0xf000)) {
		return true;
	}
	RFSFile *file = r_fs_file_new (dir->g->root, name);
	ext2_fill (dir->g, file, inode, id);
	if (deleted) {
		file->flags |= R_FS_FILE_DELETED | R_FS_FILE_HEURISTIC;
		int allocated = ext2_allocated (dir->g, id, true);
		if (allocated != 0 || !r_read_le32 (inode + 20)) {
			file->flags |= R_FS_FILE_CONFLICT;
		}
	}
	r_list_append (dir->list, file);
	return true;
}

static bool ext2_carve_inode(Ext2Geometry *g, ut32 id, const ut8 *inode, bool allocated, void *user) {
	ut16 mode = r_read_le16 (inode) & 0xf000;
	if (id < g->first_inode || allocated || !r_read_le32 (inode + 20) || r_read_le16 (inode + 26)
			|| (mode != 0x8000 && mode != 0x4000 && mode != 0xa000)) {
		return true;
	}
	char *name = r_str_newf ("inode-%u", id);
	RFSFile *file = r_fs_file_new (g->root, name);
	free (name);
	ext2_fill (g, file, inode, id);
	file->flags = R_FS_FILE_DELETED | R_FS_FILE_HEURISTIC;
	r_list_append (user, file);
	return true;
}

static RList *ext2_carve_inodes(Ext2Geometry *g) {
	RList *result = r_list_newf ((RListFree)r_fs_file_free);
	if (!ext2_scan_inodes (g, ext2_carve_inode, result)) {
		R_LOG_WARN ("Damaged ext2 inode table: retaining readable entries");
	}
	return result;
}

static RList *FSP(_forensic_dir)(RFSRoot *root, const char *path, ut64 id, int view) {
	Ext2Geometry g;
	if (!ext2_geometry (root, &g)) {
		return view & R_FS_VIEW_NORMAL? FSP(_dir) (root, path, id, view): NULL;
	}
	if (!id && (view & R_FS_VIEW_DELETED)) {
		return ext2_carve_inodes (&g);
	}
	ut32 number = id == UT64_MAX? ext2_lookup (&g, path): id <= g.inodes? id: 0;
	ut8 inode[128];
	if (!number || !ext2_inode (&g, number, inode) || (r_read_le16 (inode) & 0xf000) != 0x4000
			|| (r_read_le32 (inode + 32) & 0x10000000)) {
		return view & R_FS_VIEW_NORMAL? FSP(_dir) (root, path, id, view): NULL;
	}
	RList *result = r_list_newf ((RListFree)r_fs_file_free);
	Ext2Directory dir = { &g, result, view };
	Ext2BitmapCache cache = {0};
	g.cache = &cache;
	ext2_entries (&g, inode, number, ext2_directory_cb, &dir, view & R_FS_VIEW_DELETED);
	free (cache.data);
	r_bitset_free (cache.metadata);
	return result;
}

static int ext2_bad_block(ut64 block, ut64 logical, ut64 size, unsigned depth, ut32 flags, void *user) {
	return !block || depth || r_bitset_test (user, block) || r_bitset_set (user, block)? R_FS_WALK_COMPLETE: R_FS_WALK_ERROR;
}

static bool ext2_bad_blocks(Ext2Geometry *g, RBitset **bad) {
	ut8 inode[128];
	*bad = NULL;
	if (!ext2_inode (g, 1, inode)) {
		return false;
	}
	if (!r_read_le32 (inode + 28)) {
		return true;
	}
	*bad = r_bitset_new ();
	if (!*bad) {
		return false;
	}
	ut64 capacity = ext2_capacity (g, inode);
	return ext2_walk_inode (g, inode, 1, capacity, ext2_bad_block, *bad) == R_FS_WALK_COMPLETE;
}

static int FSP(_forensic_ranges)(RFSRoot *root, ut32 flags, RFSRangeCb cb, void *user) {
	Ext2Geometry g;
	if (!ext2_geometry (root, &g)) {
		return R_FS_WALK_UNSUPPORTED;
	}
	if (!flags || (flags & ~(R_FS_RANGE_FREE | R_FS_RANGE_ALLOCATED | R_FS_RANGE_ORPHAN | R_FS_RANGE_BAD | R_FS_RANGE_UNKNOWN))) {
		return R_FS_WALK_UNSUPPORTED;
	}
	RBitset *owners = flags & R_FS_RANGE_ORPHAN? ext2_owners (&g): NULL;
	if ((flags & R_FS_RANGE_ORPHAN) && !owners) {
		return R_FS_WALK_ERROR;
	}
	RBitset *bad = NULL;
	bool bad_known = ext2_bad_blocks (&g, &bad);
	if (!bad_known) {
		r_bitset_free (bad);
		bad = NULL;
	}
	ut8 *bitmap = malloc (g.block_size);
	if (!bitmap) {
		r_bitset_free (owners);
		r_bitset_free (bad);
		return R_FS_WALK_ERROR;
	}
	Ext2BitmapCache cache = {0};
	g.cache = &cache;
	RFSRange run = {0};
	ut32 group;
	int status = bad_known? R_FS_WALK_COMPLETE: R_FS_WALK_ERROR;
	for (group = 0; group < g.groups; group++) {
		bool known = ext2_bitmap (&g, group, false, bitmap);
		if (!known) {
			R_LOG_WARN ("Unreadable ext2 allocation bitmap for group %u", group);
			status = R_FS_WALK_ERROR;
		}
		ut64 first = (ut64)g.first + (ut64)group * g.blocks_per_group;
		ut32 i, count = R_MIN ((ut64)g.blocks_per_group, g.blocks - first);
		for (i = 0; i < count; i++) {
			ut32 state = !known? R_FS_RANGE_UNKNOWN: bitmap[i / 8] & (1 << (i % 8))? R_FS_RANGE_ALLOCATED: R_FS_RANGE_FREE;
			if (bad && r_bitset_test (bad, first + i)) {
				state = R_FS_RANGE_BAD;
			}
			if (owners && state == R_FS_RANGE_ALLOCATED && !r_bitset_test (owners, first + i)) {
				state |= R_FS_RANGE_ORPHAN;
			}
			ut64 offset = (first + i) * g.block_size;
			if (run.size && (!(flags & state) || run.flags != state)) {
				if (!cb (&run, user)) {
					status = R_FS_WALK_STOPPED;
					goto done;
				}
				run.size = 0;
			}
			if (flags & state) {
				if (!run.size) {
					run.logical = offset;
					run.physical = root->delta + offset;
					run.flags = state;
				}
				run.size += g.block_size;
			}
		}
	}
	if (run.size && !cb (&run, user)) {
		status = R_FS_WALK_STOPPED;
	}
 done:
	r_bitset_free (cache.metadata);
	r_bitset_free (bad);
	r_bitset_free (owners);
	free (bitmap);
	return status;
}

static bool FSP(_forensic_mount)(RFSRoot *root) {
	bool mounted = FSP(_mount) (root);
	Ext2Geometry g;
	ut8 inode[128];
	ut64 blocks = 0;
	if (!mounted && ext2_geometry (root, &g) && ext2_inode (&g, 2, inode)
			&& (r_read_le16 (inode) & 0xf000) == 0x4000
			&& !(r_read_le32 (inode + 32) & 0x10000000)
			&& (!(r_read_le32 (inode + 32) & 0x80000)
				|| ext2_walk_inode (&g, inode, 2, ext2_size (inode), ext2_count_block, &blocks) == R_FS_WALK_COMPLETE)) {
		R_LOG_WARN ("Damaged ext2 root directory: enabling inode and allocation inspection");
		return true;
	}
	return mounted;
}
