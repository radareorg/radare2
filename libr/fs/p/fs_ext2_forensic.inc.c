/* radare - LGPL - Copyright 2026 - pancake */

typedef struct {
	RFSRoot *root;
	ut32 blocks, inodes, first, block_size, blocks_per_group, inodes_per_group;
	ut32 groups, inode_size, incompat, ro_compat, reserved_gdt, first_inode, creator_os;
} Ext2Geometry;

typedef struct {
	GrubFS *grub;
	ut8 inode[128];
	bool recovery;
	bool contiguous;
	RBitmap *owners;
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
	g->reserved_gdt = r_read_le16 (sb + 206);
	if (!g->blocks_per_group || !g->inodes_per_group || g->blocks_per_group > g->block_size * 8
			|| g->inodes_per_group > g->block_size * 8 || g->first >= g->blocks || !g->inodes
			|| g->first != (g->block_size == 1024? 1: 0)
			|| g->inode_size < 128 || g->inode_size > g->block_size || (g->inode_size & (g->inode_size - 1))
			|| (g->incompat & ~2U) || (g->ro_compat & ~7U) || root->delta > UT64_MAX - (ut64)g->blocks * g->block_size) {
		return false;
	}
	g->groups = ((ut64)g->blocks - g->first + g->blocks_per_group - 1) / g->blocks_per_group;
	return ((ut64)g->inodes + g->inodes_per_group - 1) / g->inodes_per_group <= g->groups;
}

static bool ext2_group(Ext2Geometry *g, ut32 group, ut8 *desc) {
	return group < g->groups && ext2_disk (g, (ut64)(g->first + 1) * g->block_size + (ut64)group * 32, desc, 32);
}

static ut64 ext2_inode_offset(Ext2Geometry *g, ut64 id) {
	ut8 desc[32];
	if (!id || id > g->inodes || !ext2_group (g, (id - 1) / g->inodes_per_group, desc)) {
		return UT64_MAX;
	}
	ut32 table = r_read_le32 (desc + 8);
	ut64 offset = (ut64)table * g->block_size + ((id - 1) % g->inodes_per_group) * g->inode_size;
	return table && table < g->blocks && offset <= (ut64)g->blocks * g->block_size - 128? offset: UT64_MAX;
}

static bool ext2_inode(Ext2Geometry *g, ut64 id, ut8 *inode) {
	ut64 offset = ext2_inode_offset (g, id);
	return offset != UT64_MAX && ext2_disk (g, offset, inode, 128);
}

static int ext2_allocated(Ext2Geometry *g, ut64 number, bool inode) {
	ut64 index = inode? number - 1: number - g->first;
	ut32 per_group = inode? g->inodes_per_group: g->blocks_per_group;
	ut8 desc[32], byte;
	if ((inode && (!number || number > g->inodes)) || (!inode && (number < g->first || number >= g->blocks))
			|| !ext2_group (g, index / per_group, desc)) {
		return -1;
	}
	ut32 bitmap = r_read_le32 (desc + (inode? 4: 0));
	if (!bitmap || bitmap >= g->blocks || !ext2_disk (g, (ut64)bitmap * g->block_size + (index % per_group) / 8, &byte, 1)) {
		return -1;
	}
	return (byte >> (index % per_group % 8)) & 1;
}

static ut64 ext2_size(const ut8 *inode) {
	ut64 size = r_read_le32 (inode + 4);
	if ((r_read_le16 (inode) & 0xf000) == 0x8000) {
		size |= (ut64)r_read_le32 (inode + 108) << 32;
	}
	return size;
}

static bool ext2_inline_link(Ext2Geometry *g, const ut8 *inode) {
	return (r_read_le16 (inode) & 0xf000) == 0xa000 && ext2_size (inode) <= 60
		&& r_read_le32 (inode + 28) <= (r_read_le32 (inode + 104)? g->block_size / 512: 0);
}

// Resolve one classic block map, stopping on cycles and invalid pointers.
static bool ext2_block(Ext2Geometry *g, const ut8 *inode, ut64 logical, RBitmap *owners, ut32 *block) {
	ut64 count = g->block_size / 4, span = count;
	ut32 level, depth, seen[3];
	if (r_read_le32 (inode + 32) & (0x80000 | 0x10000000)) {
		return false;
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
		if (*block < g->first || *block >= g->blocks || (owners && (ext2_allocated (g, *block, false) != 0 || r_bitmap_test (owners, *block)))) {
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

static bool ext2_file_block(Ext2Geometry *g, Ext2File *entry, ut64 logical, ut32 *block) {
	if (!entry->contiguous) {
		return ext2_block (g, entry->inode, logical, entry->owners, block);
	}
	ut32 first = r_read_le32 (entry->inode + 40);
	if (!first || first >= g->blocks || logical >= g->blocks - first) {
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

typedef int (*Ext2BlockCb)(ut32 block, ut64 logical, ut64 size, unsigned depth, void *user);

typedef struct {
	Ext2Geometry *g;
	Ext2BlockCb cb;
	void *user;
	RBitset *visited;
} Ext2Walk;

static int ext2_walk_tree(Ext2Walk *walk, ut32 block, unsigned depth, ut64 logical, ut64 span, ut64 size) {
	Ext2Geometry *g = walk->g;
	if (block && (block < g->first || block >= g->blocks)) {
		return R_FS_WALK_ERROR;
	}
	if (block && !r_bitset_set (walk->visited, block)) {
		return R_FS_WALK_ERROR;
	}
	if (!block || !depth) {
		return walk->cb (block, logical, size, 0, walk->user);
	}
	int status = walk->cb (block, logical, g->block_size, depth, walk->user);
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

static int ext2_walk_inode(Ext2Geometry *g, const ut8 *inode, ut64 size, Ext2BlockCb cb, void *user) {
	if (r_read_le32 (inode + 32) & (0x80000 | 0x10000000)) {
		return R_FS_WALK_UNSUPPORTED;
	}
	Ext2Walk walk = { .g = g, .cb = cb, .user = user, .visited = r_bitset_new () };
	if (!walk.visited) {
		return R_FS_WALK_ERROR;
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

static ut64 ext2_capacity(Ext2Geometry *g) {
	ut64 span = g->block_size, capacity = 12 * span;
	unsigned depth;
	for (depth = 0; depth < 3; depth++) {
		span *= g->block_size / 4;
		capacity += span;
	}
	return capacity;
}

static int ext2_owner_block(ut32 block, ut64 logical, ut64 size, unsigned depth, void *user) {
	if (block) {
		r_bitmap_set (user, block);
	}
	return R_FS_WALK_COMPLETE;
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
	for (group = 0; ok && group < g->groups && (ut64)group * g->inodes_per_group < g->inodes; group++) {
		ut8 desc[32];
		if (!ext2_group (g, group, desc)) {
			ok = false;
			break;
		}
		ut32 map = r_read_le32 (desc + 4), table = r_read_le32 (desc + 8);
		if (!map || map >= g->blocks || !table || table >= g->blocks
				|| !ext2_disk (g, (ut64)map * g->block_size, bitmap, g->block_size)) {
			ok = false;
			break;
		}
		ut64 first = (ut64)group * g->inodes_per_group;
		ut32 i, count = R_MIN ((ut64)g->inodes_per_group, g->inodes - first);
		ut32 per_block = g->block_size / g->inode_size;
		for (i = 0; i < count; i++) {
			if (!(i % per_block) && !ext2_disk (g, (ut64)table * g->block_size + (ut64)i * g->inode_size, data, g->block_size)) {
				ok = false;
				break;
			}
			if (!cb (g, first + i + 1, data + (i % per_block) * g->inode_size,
					(bitmap[i / 8] >> (i % 8)) & 1, user)) {
				ok = false;
				break;
			}
		}
	}
	free (bitmap);
	free (data);
	return ok;
}

static bool ext2_owner_inode(Ext2Geometry *g, ut32 id, const ut8 *inode, bool allocated, void *user) {
	if (id >= g->first_inode && !allocated && r_read_le32 (inode + 20)) {
		return true;
	}
	ut64 capacity = ext2_capacity (g);
	ut16 mode = r_read_le16 (inode) & 0xf000;
	ut32 acl = r_read_le32 (inode + 104);
	bool inline_link = ext2_inline_link (g, inode);
	if (!inline_link && (mode == 0x8000 || mode == 0x4000 || mode == 0xa000 || id < g->first_inode)
			&& ext2_walk_inode (g, inode, capacity, ext2_owner_block, user) != R_FS_WALK_COMPLETE) {
		return false;
	}
	if (acl) {
		if (acl >= g->blocks || acl < g->first) {
			return false;
		}
		r_bitmap_set (user, acl);
	}
	return true;
}

static RBitmap *ext2_owners(Ext2Geometry *g) {
	RBitmap *used = r_bitmap_new (g->blocks);
	if (!used) {
		return NULL;
	}
	ut32 group;
	for (group = 0; group < g->groups; group++) {
		ut8 desc[32];
		if (!ext2_group (g, group, desc)) {
			goto failure;
		}
		ut32 bitmap = r_read_le32 (desc), inodes = r_read_le32 (desc + 4), table = r_read_le32 (desc + 8);
		ut64 count = ((ut64)g->inodes_per_group * g->inode_size + g->block_size - 1) / g->block_size;
		if (!bitmap || bitmap >= g->blocks || !inodes || inodes >= g->blocks || !table || table >= g->blocks
				|| count > g->blocks - table) {
			goto failure;
		}
		r_bitmap_set (used, bitmap);
		r_bitmap_set (used, inodes);
		ut64 block;
		for (block = table; block < table + count; block++) {
			r_bitmap_set (used, block);
		}
		if (ext2_super_group (group, g->ro_compat & 1)) {
			ut64 first = g->first + (ut64)group * g->blocks_per_group;
			ut64 reserved = 1 + ((ut64)g->groups * 32 + g->block_size - 1) / g->block_size + g->reserved_gdt;
			if (reserved > g->blocks - first) {
				goto failure;
			}
			for (block = first; block < first + reserved; block++) {
				r_bitmap_set (used, block);
			}
		}
	}
	if (!ext2_scan_inodes (g, ext2_owner_inode, used)) {
		goto failure;
	}
	return used;
 failure:
	r_bitmap_free (used);
	return NULL;
}

static int ext2_count_block(ut32 block, ut64 logical, ut64 size, unsigned depth, void *user) {
	if (block) {
		(*(ut64 *)user)++;
	}
	return R_FS_WALK_COMPLETE;
}

static bool ext2_recovery_owners(Ext2Geometry *g, Ext2File *entry) {
	if (!entry->recovery) {
		return true;
	}
	if (!entry->checked) {
		entry->owners = ext2_owners (g);
		entry->checked = true;
		ut64 blocks = r_read_le32 (entry->inode + 104)? 1: 0;
		int status = ext2_walk_inode (g, entry->inode, ext2_capacity (g), ext2_count_block, &blocks);
		entry->sparse_known = status == R_FS_WALK_COMPLETE
			&& blocks * (g->block_size / 512) == r_read_le32 (entry->inode + 28);
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

static int ext2_extent_block(ut32 block, ut64 logical, ut64 size, unsigned depth, void *user) {
	Ext2Extents *output = user;
	Ext2File *entry = output->file->ptr;
	if (!block && entry->recovery && !entry->sparse_known && !entry->contiguous) {
		return R_FS_WALK_ERROR;
	}
	int allocated = block? ext2_allocated (output->g, block, false): 0;
	if (allocated < 0 || (entry->recovery && block && (allocated || r_bitmap_test (entry->owners, block)))) {
		if (allocated > 0 || (block && entry->owners && r_bitmap_test (entry->owners, block))) {
			output->file->flags |= R_FS_FILE_CONFLICT;
		}
		return R_FS_WALK_ERROR;
	}
	if (depth) {
		return R_FS_WALK_COMPLETE;
	}
	ut32 flags = !block? R_FS_RANGE_SPARSE: allocated? R_FS_RANGE_ALLOCATED: R_FS_RANGE_FREE;
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
	if (ext2_inline_link (&g, entry->inode)) {
		ut64 offset = ext2_inode_offset (&g, file->id);
		if (offset == UT64_MAX) {
			return R_FS_WALK_ERROR;
		}
		RFSRange range = { 0, file->root->delta + offset + 40, file->size, R_FS_RANGE_ALLOCATED };
		return !range.size || cb (&range, user)? R_FS_WALK_COMPLETE: R_FS_WALK_STOPPED;
	}
	if (!ext2_recovery_owners (&g, entry)) {
		file->flags |= R_FS_FILE_PARTIAL;
		return R_FS_WALK_ERROR;
	}
	Ext2Extents output = { .g = &g, .file = file, .cb = cb, .user = user };
	int status = R_FS_WALK_COMPLETE;
	if (entry->contiguous) {
		ut64 offset;
		for (offset = 0; offset < file->size; offset += g.block_size) {
			ut32 block;
			if (!ext2_file_block (&g, entry, offset / g.block_size, &block)) {
				status = R_FS_WALK_ERROR;
				break;
			}
			status = ext2_extent_block (block, offset, R_MIN ((ut64)g.block_size, file->size - offset), 0, &output);
			if (status != R_FS_WALK_COMPLETE) {
				break;
			}
		}
	} else {
		status = ext2_walk_inode (&g, entry->inode, file->size, ext2_extent_block, &output);
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
		ut32 block;
		if (file->type != 'f' || !ext2_file_block (&g, entry, 0, &block)) {
			free (entry);
			r_fs_file_free (file);
			return NULL;
		}
		file->flags |= R_FS_FILE_HEURISTIC;
	}
	if (!allocated) {
		file->flags |= R_FS_FILE_DELETED;
	}
	ut32 block;
	if (ext2_inline_link (&g, inode)) {
		ut64 offset = ext2_inode_offset (&g, id);
		if (offset != UT64_MAX) {
			file->off = root->delta + offset + 40;
		}
	} else if (file->size && ext2_block (&g, inode, 0, NULL, &block) && block) {
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
	if (ext2_inline_link (&g, entry->inode)) {
		len = R_MIN ((ut64)len, file->size - addr);
		memcpy (file->data, entry->inode + 40 + addr, len);
		return len;
	}
	if (!ext2_recovery_owners (&g, entry)) {
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
		ut32 block;
		ut64 off = addr + done;
		if (!ext2_file_block (&g, entry, off / g.block_size, &block)
				|| (entry->recovery && !block && !entry->sparse_known)
				|| (entry->recovery && block && (ext2_allocated (&g, block, false) != 0 || r_bitmap_test (entry->owners, block)))) {
			file->flags |= R_FS_FILE_PARTIAL | R_FS_FILE_CONFLICT;
			break;
		}
		int chunk = R_MIN (len - done, g.block_size - off % g.block_size);
		if (block) {
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
	r_bitmap_free (entry->owners);
	free (entry);
	file->ptr = NULL;
}

typedef bool (*Ext2DirCb)(ut32 id, const char *name, bool deleted, void *user);

static bool ext2_entries(Ext2Geometry *g, const ut8 *inode, Ext2DirCb cb, void *user, bool slack) {
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
		ut32 block;
		if (!ext2_block (g, inode, offset / g->block_size, NULL, &block) || !block
				|| !ext2_disk (g, (ut64)block * g->block_size, buf, g->block_size)) {
			ok = false;
			break;
		}
		ut32 pos = 0, end = R_MIN ((ut64)g->block_size, size - offset), next = 0;
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
			if (slack) {
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
		ext2_entries (g, inode, ext2_lookup_cb, &lookup, false);
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
					ut32 block;
					int chunk = R_MIN ((ut64)g->block_size, size - offset);
					if (!ext2_block (g, inode, offset / g->block_size, NULL, &block) || !block
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
			ut32 block;
			file->off = ext2_block (&g, entry->inode, 0, NULL, &block) && block?
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
			|| (r_read_le32 (inode + 32) & (0x80000 | 0x10000000))) {
		return view & R_FS_VIEW_NORMAL? FSP(_dir) (root, path, id, view): NULL;
	}
	RList *result = r_list_newf ((RListFree)r_fs_file_free);
	Ext2Directory dir = { &g, result, view };
	ext2_entries (&g, inode, ext2_directory_cb, &dir, view & R_FS_VIEW_DELETED);
	return result;
}

static int ext2_bad_block(ut32 block, ut64 logical, ut64 size, unsigned depth, void *user) {
	if (block && !depth) {
		r_bitmap_set (user, block);
	}
	return R_FS_WALK_COMPLETE;
}

static bool ext2_bad_blocks(Ext2Geometry *g, RBitmap **bad) {
	ut8 inode[128];
	*bad = NULL;
	if (!ext2_inode (g, 1, inode)) {
		return false;
	}
	if (!r_read_le32 (inode + 28)) {
		return true;
	}
	*bad = r_bitmap_new (g->blocks);
	if (!*bad) {
		return false;
	}
	ut64 capacity = ext2_capacity (g);
	return ext2_walk_inode (g, inode, capacity, ext2_bad_block, *bad) == R_FS_WALK_COMPLETE;
}

static int FSP(_forensic_ranges)(RFSRoot *root, ut32 flags, RFSRangeCb cb, void *user) {
	Ext2Geometry g;
	if (!ext2_geometry (root, &g)) {
		return R_FS_WALK_UNSUPPORTED;
	}
	if (!flags || (flags & ~(R_FS_RANGE_FREE | R_FS_RANGE_ALLOCATED | R_FS_RANGE_ORPHAN | R_FS_RANGE_BAD | R_FS_RANGE_UNKNOWN))) {
		return R_FS_WALK_UNSUPPORTED;
	}
	RBitmap *owners = flags & R_FS_RANGE_ORPHAN? ext2_owners (&g): NULL;
	if ((flags & R_FS_RANGE_ORPHAN) && !owners) {
		return R_FS_WALK_ERROR;
	}
	RBitmap *bad = NULL;
	if (!ext2_bad_blocks (&g, &bad)) {
		r_bitmap_free (owners);
		r_bitmap_free (bad);
		return R_FS_WALK_ERROR;
	}
	ut8 *bitmap = malloc (g.block_size);
	if (!bitmap) {
		r_bitmap_free (owners);
		r_bitmap_free (bad);
		return R_FS_WALK_ERROR;
	}
	RFSRange run = {0};
	ut32 group;
	int status = R_FS_WALK_COMPLETE;
	for (group = 0; group < g.groups; group++) {
		ut8 desc[32];
		bool known = ext2_group (&g, group, desc);
		ut32 block = known? r_read_le32 (desc): 0;
		known = known && block && block < g.blocks && ext2_disk (&g, (ut64)block * g.block_size, bitmap, g.block_size);
		if (!known) {
			R_LOG_WARN ("Unreadable ext2 allocation bitmap for group %u", group);
			status = R_FS_WALK_ERROR;
		}
		ut64 first = (ut64)g.first + (ut64)group * g.blocks_per_group;
		ut32 i, count = R_MIN ((ut64)g.blocks_per_group, g.blocks - first);
		for (i = 0; i < count; i++) {
			ut32 state = !known? R_FS_RANGE_UNKNOWN: bitmap[i / 8] & (1 << (i % 8))? R_FS_RANGE_ALLOCATED: R_FS_RANGE_FREE;
			if (bad && r_bitmap_test (bad, first + i)) {
				state = R_FS_RANGE_BAD;
			}
			if (owners && state == R_FS_RANGE_ALLOCATED && !r_bitmap_test (owners, first + i)) {
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
	r_bitmap_free (bad);
	r_bitmap_free (owners);
	free (bitmap);
	return status;
}

static bool FSP(_forensic_mount)(RFSRoot *root) {
	bool mounted = FSP(_mount) (root);
	Ext2Geometry g;
	ut8 inode[128];
	if (!mounted && ext2_geometry (root, &g) && ext2_inode (&g, 2, inode)
			&& (r_read_le16 (inode) & 0xf000) == 0x4000
			&& !(r_read_le32 (inode + 32) & (0x80000 | 0x10000000))) {
		R_LOG_WARN ("Damaged ext2 root directory: enabling inode and allocation inspection");
		return true;
	}
	return mounted;
}
