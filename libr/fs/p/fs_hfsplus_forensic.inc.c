/* radare - LGPL - Copyright 2026 - pancake */

#include <r_vec.h>

// R2R db/cmd/cmd_fs_hfsplus_forensic

#define HFS_DELETED_ID (1ULL << 63)

typedef struct {
	ut64 logical, physical, size;
} HfsRun;
R_VEC_TYPE (RVecHfsRun, HfsRun);

typedef struct {
	RVecHfsRun runs;
	ut64 size;
	ut32 blocks;
	int status;
} HfsFork;

typedef struct {
	HfsFork fork;
	ut32 node_size, nodes, root, first, last, records, depth;
	ut64 map_bits, leaf_count;
	ut32 previous_leaf, previous_next;
	RBitset *allocated, *visited, *map_nodes;
	bool complete, initialized;
} HfsTree;

typedef struct {
	ut32 cnid, start;
	ut8 type;
	bool live;
	ut8 extents[64];
} HfsOverflow;
R_VEC_TYPE (RVecHfsOverflow, HfsOverflow);

typedef struct {
	ut64 id, size, time;
	ut32 cnid, parent, flags, uid, gid;
	ut16 mode;
	char type;
	char *name;
	ut8 data[80], resource[80];
	bool compressed;
} HfsEntry;

typedef struct {
	RFSRoot *root;
	GrubFS *grub;
	ut64 base, size;
	ut32 block_size, blocks, volume_flags, journal;
	HfsFork bitmap, startup;
	HfsTree catalog, overflow, attributes;
	RVecHfsOverflow extra;
	RVecHfsRun owners, bad;
	RList *entries;
	HtUP *ids, *live, *children;
	ut64 bitmap_page;
	ut32 bitmap_size;
	ut8 bitmap_cache[4096];
	ut32 attribute_file, attribute_blocks, attribute_next, attribute_name_size;
	ut8 attribute_name[510];
	bool attribute_open;
	bool bitmap_known, geometry, native, case_sensitive, ready, owners_complete;
} HfsFS;

typedef struct {
	HfsFS *fs;
	HfsEntry *entry;
	GrubFS *grub;
	HfsFork data;
	ut64 readable;
	bool recovery, salvage, planned;
} HfsFile;

typedef int (*HfsRecordCb)(HfsFS *fs, const ut8 *record, ut32 length, ut64 location, bool live);

static void hfs_fork_fini(HfsFork *fork) {
	RVecHfsRun_fini (&fork->runs);
}

static bool hfs_disk(HfsFS *fs, ut64 offset, ut8 *buffer, int length) {
	return length >= 0 && offset <= fs->size && (ut64)length <= fs->size - offset
		&& fs->root->iob.read_at (fs->root->iob.io, fs->root->delta + fs->base + offset, buffer, length) == length;
}

static HfsRun *hfs_run_at(RVecHfsRun *runs, ut64 offset) {
	size_t low = 0, high = RVecHfsRun_length (runs);
	while (low < high) {
		size_t mid = low + (high - low) / 2;
		HfsRun *run = RVecHfsRun_at (runs, mid);
		if (offset < run->logical) {
			high = mid;
		} else if (offset - run->logical >= run->size) {
			low = mid + 1;
		} else {
			return run;
		}
	}
	return NULL;
}

static bool hfs_fork_read(HfsFS *fs, HfsFork *fork, ut64 offset, ut8 *buffer, int length) {
	if (length < 0 || offset > fork->size || (ut64)length > fork->size - offset) {
		return false;
	}
	int done = 0;
	while (done < length) {
		HfsRun *run = hfs_run_at (&fork->runs, offset + done);
		if (!run) {
			return false;
		}
		ut64 within = offset + done - run->logical;
		int chunk = R_MIN ((ut64)(length - done), run->size - within);
		if (!hfs_disk (fs, run->physical + within, buffer + done, chunk)) {
			return false;
		}
		done += chunk;
	}
	return true;
}

static bool hfs_extents_add(HfsFS *fs, HfsFork *fork, const ut8 *extents) {
	HfsRun *last = RVecHfsRun_last (&fork->runs);
	ut64 logical = last? last->logical + last->size: 0;
	bool end = false;
	unsigned i;
	for (i = 0; i < 8; i++) {
		ut32 start = r_read_be32 (extents + i * 8), count = r_read_be32 (extents + i * 8 + 4);
		if (!count) {
			if (start) {
				return false;
			}
			end = true;
			continue;
		}
		if (end || start >= fs->blocks || count > fs->blocks - start
				|| logical / fs->block_size > fork->blocks || count > fork->blocks - logical / fs->block_size) {
			return false;
		}
		HfsRun *run = RVecHfsRun_emplace_back (&fork->runs);
		if (!run) {
			return false;
		}
		*run = (HfsRun){ logical, (ut64)start * fs->block_size, (ut64)count * fs->block_size };
		logical += run->size;
	}
	return true;
}

static void hfs_fork_init(HfsFS *fs, HfsFork *fork, const ut8 *descriptor) {
	fork->size = r_read_be64 (descriptor);
	fork->blocks = r_read_be32 (descriptor + 12);
	fork->status = R_FS_WALK_ERROR;
	if (fork->size <= INT64_MAX && fork->blocks <= fs->blocks && fork->size <= (ut64)fork->blocks * fs->block_size
			&& hfs_extents_add (fs, fork, descriptor + 16)) {
		fork->status = R_FS_WALK_COMPLETE;
	}
}

static int hfs_overflow_compare(const HfsOverflow *a, const HfsOverflow *b) {
	if (a->cnid != b->cnid) {
		return a->cnid < b->cnid? -1: 1;
	}
	if (a->type != b->type) {
		return a->type < b->type? -1: 1;
	}
	if (a->start != b->start) {
		return a->start < b->start? -1: 1;
	}
	return a->live == b->live? 0: a->live? -1: 1;
}

static HfsOverflow *hfs_overflow_find(HfsFS *fs, ut32 cnid, ut8 type, ut32 start, bool deleted) {
	HfsOverflow key = { .cnid = cnid, .type = type, .start = start, .live = !deleted };
	size_t low = 0, high = RVecHfsOverflow_length (&fs->extra);
	while (low < high) {
		size_t mid = low + (high - low) / 2;
		if (hfs_overflow_compare (RVecHfsOverflow_at (&fs->extra, mid), &key) < 0) {
			low = mid + 1;
		} else {
			high = mid;
		}
	}
	HfsOverflow *found = NULL;
	while (low < RVecHfsOverflow_length (&fs->extra)) {
		HfsOverflow *entry = RVecHfsOverflow_at (&fs->extra, low++);
		if (hfs_overflow_compare (entry, &key)) {
			break;
		}
		if (found && memcmp (found->extents, entry->extents, sizeof (found->extents))) {
			return NULL;
		}
		found = entry;
	}
	return found;
}

static void hfs_fork_complete(HfsFS *fs, HfsFork *fork, ut32 cnid, ut8 type, bool deleted) {
	while (fork->status == R_FS_WALK_COMPLETE) {
		HfsRun *last = RVecHfsRun_last (&fork->runs);
		ut64 blocks = last? (last->logical + last->size) / fs->block_size: 0;
		if (blocks == fork->blocks) {
			return;
		}
		HfsOverflow *entry = hfs_overflow_find (fs, cnid, type, blocks, deleted);
		if (!entry || !hfs_extents_add (fs, fork, entry->extents)) {
			break;
		}
		HfsRun *next = RVecHfsRun_last (&fork->runs);
		if (!next || (next->logical + next->size) / fs->block_size <= blocks) {
			break;
		}
	}
	fork->status = R_FS_WALK_ERROR;
}

static bool hfs_node_bounds(const ut8 *node, ut32 size) {
	ut32 count = r_read_be16 (node + 10);
	if (count > (size - 16) / 2) {
		return false;
	}
	ut32 table = size - (count + 1) * 2, previous = 14, i;
	for (i = 0; i <= count; i++) {
		ut32 offset = r_read_be16 (node + size - (i + 1) * 2);
		if (offset < previous || offset > table || (offset & 1) || (!i && offset != 14)
				|| (i && offset == previous)) {
			return false;
		}
		previous = offset;
	}
	return true;
}

static const ut8 *hfs_node_record(const ut8 *node, ut32 size, ut32 index, ut32 *length) {
	ut32 start = r_read_be16 (node + size - (index + 1) * 2);
	ut32 end = r_read_be16 (node + size - (index + 2) * 2);
	*length = end - start;
	return node + start;
}

static int hfs_node_allocated(HfsTree *tree, ut32 id) {
	return id < tree->map_bits? r_bitset_test (tree->allocated, id): -1;
}

static bool hfs_tree_map(HfsTree *tree, const ut8 *data, ut32 length) {
	ut64 i, bits = R_MIN ((ut64)length * 8, tree->nodes - tree->map_bits);
	for (i = 0; i < bits; i++) {
		if ((data[i / 8] & (128 >> (i % 8))) && !r_bitset_set (tree->allocated, tree->map_bits + i)) {
			return false;
		}
	}
	tree->map_bits += bits;
	return true;
}

static bool hfs_tree_init(HfsFS *fs, HfsTree *tree) {
	ut8 header[120];
	if (!hfs_fork_read (fs, &tree->fork, 0, header, sizeof (header)) || header[8] != 1
			|| r_read_be16 (header + 10) != 3) {
		return false;
	}
	tree->node_size = r_read_be16 (header + 32);
	tree->depth = r_read_be16 (header + 14);
	tree->root = r_read_be32 (header + 16);
	tree->records = r_read_be32 (header + 20);
	tree->first = r_read_be32 (header + 24);
	tree->last = r_read_be32 (header + 28);
	tree->nodes = r_read_be32 (header + 36);
	if (tree->node_size < 512 || (tree->node_size & (tree->node_size - 1)) || !tree->nodes || tree->depth > 32
			|| tree->nodes > tree->fork.size / tree->node_size || tree->root >= tree->nodes
			|| tree->first >= tree->nodes || tree->last >= tree->nodes) {
		return false;
	}
	tree->allocated = r_bitset_new ();
	tree->visited = r_bitset_new ();
	tree->map_nodes = r_bitset_new ();
	ut8 *node = malloc (tree->node_size);
	if (!tree->allocated || !tree->visited || !tree->map_nodes || !node) {
		free (node);
		return false;
	}
	tree->initialized = true;
	tree->complete = tree->fork.status == R_FS_WALK_COMPLETE;
	ut32 id = 0;
	while (true) {
		if (id >= tree->nodes || !r_bitset_set (tree->map_nodes, id)
				|| !hfs_fork_read (fs, &tree->fork, (ut64)id * tree->node_size, node, tree->node_size)
				|| !hfs_node_bounds (node, tree->node_size) || node[8] != (id? 2: 1)
				|| r_read_be16 (node + 10) != (id? 1: 3)) {
			tree->complete = false;
			break;
		}
		ut32 length;
		const ut8 *map = hfs_node_record (node, tree->node_size, id? 0: 2, &length);
		if (!hfs_tree_map (tree, map, length)) {
			tree->complete = false;
			break;
		}
		id = r_read_be32 (node);
		if (!id) {
			break;
		}
	}
	tree->complete &= tree->map_bits == tree->nodes && hfs_node_allocated (tree, 0) == 1;
	free (node);
	return true;
}

static bool hfs_tree_walk(HfsFS *fs, HfsTree *tree, ut32 id, ut32 height, HfsRecordCb callback) {
	if (!id || id >= tree->nodes || !height || !r_bitset_set (tree->visited, id)) {
		return false;
	}
	ut8 *node = malloc (tree->node_size);
	if (!node) {
		return false;
	}
	bool complete = hfs_fork_read (fs, &tree->fork, (ut64)id * tree->node_size, node, tree->node_size)
		&& hfs_node_bounds (node, tree->node_size) && node[9] == height && node[8] == (height == 1? 255: 0);
	if (!complete) {
		free (node);
		return false;
	}
	complete = hfs_node_allocated (tree, id) == 1;
	if (height == 1) {
		complete &= r_read_be32 (node + 4) == tree->previous_leaf;
		complete &= tree->previous_leaf? tree->previous_next == id: tree->first == id;
		tree->previous_leaf = id;
		tree->previous_next = r_read_be32 (node);
	}
	ut32 i, count = r_read_be16 (node + 10);
	for (i = 0; i < count; i++) {
		ut32 length;
		const ut8 *record = hfs_node_record (node, tree->node_size, i, &length);
		if (height == 1) {
			complete &= callback (fs, record, length, (ut64)id * tree->node_size + record - node, true) > 0;
			tree->leaf_count++;
		} else if (length >= 6 && r_read_be16 (record) <= length - 6 && !(r_read_be16 (record) & 1)) {
			ut32 key = r_read_be16 (record) + 2;
			complete &= hfs_tree_walk (fs, tree, r_read_be32 (record + key), height - 1, callback);
		} else {
			complete = false;
		}
	}
	free (node);
	return complete;
}

static bool hfs_tree_scan(HfsFS *fs, HfsTree *tree, HfsRecordCb callback, bool carve) {
	if (!tree->initialized) {
		return false;
	}
	if (tree->root) {
		tree->complete &= hfs_tree_walk (fs, tree, tree->root, tree->depth, callback);
	} else {
		tree->complete &= !tree->depth && !tree->records && !tree->first && !tree->last;
	}
	tree->complete &= tree->leaf_count == tree->records && !tree->previous_next
		&& tree->previous_leaf == tree->last;
	ut8 *node = malloc (tree->node_size);
	if (!node) {
		return false;
	}
	ut32 id;
	for (id = 1; id < tree->nodes; id++) {
		if (r_bitset_test (tree->map_nodes, id)) {
			if (hfs_node_allocated (tree, id) != 1) {
				tree->complete = false;
			}
			continue;
		}
		bool reached = r_bitset_test (tree->visited, id);
		if (!hfs_fork_read (fs, &tree->fork, (ut64)id * tree->node_size, node, tree->node_size)) {
			if (hfs_node_allocated (tree, id) != 0 || reached) {
				tree->complete = false;
			}
			continue;
		}
		if (!reached && hfs_node_allocated (tree, id) != 0) {
			tree->complete = false;
		}
		if (!carve || (reached && node[8] != 255)) {
			continue;
		}
		ut32 start = 14, end = tree->node_size - 2;
		if (hfs_node_bounds (node, tree->node_size)) {
			ut32 count = r_read_be16 (node + 10);
			end = tree->node_size - (count + 1) * 2;
			if (reached) {
				start = r_read_be16 (node + tree->node_size - (count + 1) * 2);
			}
		} else if (reached) {
			continue;
		}
		while (start < end) {
			int length = callback (fs, node + start, end - start, (ut64)id * tree->node_size + start, false);
			start += length > 0? (length + 1) & ~1: 2;
		}
	}
	free (node);
	return tree->complete;
}

static int hfs_physical_compare(const HfsRun *a, const HfsRun *b) {
	return a->physical < b->physical? -1: a->physical > b->physical;
}

static void hfs_merge_runs(RVecHfsRun *runs) {
	RVecHfsRun_sort (runs, hfs_physical_compare);
	size_t i, count = 0, length = RVecHfsRun_length (runs);
	for (i = 0; i < length; i++) {
		HfsRun run = *RVecHfsRun_at (runs, i);
		HfsRun *previous = count? RVecHfsRun_at (runs, count - 1): NULL;
		if (previous && run.physical <= previous->physical + previous->size) {
			previous->size = R_MAX (previous->size, run.physical + run.size - previous->physical);
		} else {
			run.logical = run.physical;
			*RVecHfsRun_at (runs, count++) = run;
		}
	}
	while (RVecHfsRun_length (runs) > count) {
		RVecHfsRun_pop_back (runs);
	}
}

static bool hfs_claim(HfsFS *fs, ut64 offset, ut64 size, bool bad) {
	if (!size) {
		return true;
	}
	if (offset >= fs->size || size > fs->size - offset) {
		return false;
	}
	ut64 start = offset / fs->block_size * fs->block_size;
	ut64 end = ((offset + size - 1) / fs->block_size + 1) * fs->block_size;
	HfsRun *run = RVecHfsRun_emplace_back (&fs->owners);
	if (!run) {
		return false;
	}
	*run = (HfsRun){ start, start, end - start };
	if (bad) {
		run = RVecHfsRun_emplace_back (&fs->bad);
		if (!run) {
			return false;
		}
		*run = (HfsRun){ start, start, end - start };
	}
	return true;
}

static bool hfs_claim_fork(HfsFS *fs, HfsFork *fork) {
	bool complete = fork->status == R_FS_WALK_COMPLETE;
	size_t i;
	for (i = 0; i < RVecHfsRun_length (&fork->runs); i++) {
		HfsRun *run = RVecHfsRun_at (&fork->runs, i);
		complete &= hfs_claim (fs, run->physical, run->size, false);
	}
	return complete;
}

static int hfs_overflow_record(HfsFS *fs, const ut8 *record, ut32 length, ut64 location, bool live) {
	if (length < 76 || r_read_be16 (record) != 10 || (record[2] != 0 && record[2] != 255)
			|| record[3] || !r_read_be32 (record + 4)) {
		return 0;
	}
	HfsFork fork = { .blocks = fs->blocks, .status = R_FS_WALK_COMPLETE };
	bool valid = hfs_extents_add (fs, &fork, record + 12) && RVecHfsRun_length (&fork.runs);
	if (valid) {
		HfsOverflow *entry = RVecHfsOverflow_emplace_back (&fs->extra);
		if (!entry) {
			valid = false;
		} else {
			*entry = (HfsOverflow){ .cnid = r_read_be32 (record + 4), .start = r_read_be32 (record + 8),
				.type = record[2], .live = live };
			memcpy (entry->extents, record + 12, sizeof (entry->extents));
		}
		if (live) {
			size_t i;
			for (i = 0; i < RVecHfsRun_length (&fork.runs); i++) {
				HfsRun *run = RVecHfsRun_at (&fork.runs, i);
				fs->owners_complete &= hfs_claim (fs, run->physical, run->size, r_read_be32 (record + 4) == 5);
			}
		}
	}
	hfs_fork_fini (&fork);
	return valid? 76: 0;
}

static char *hfs_name(const ut8 *name, ut32 length) {
	if (!length || length > 255) {
		return NULL;
	}
	ut32 i;
	for (i = 0; i < length; i++) {
		ut16 ch = r_read_be16 (name + i * 2);
		if (!ch || ch == '/' || (ch >= 0xdc00 && ch <= 0xdfff)) {
			return NULL;
		}
		if (ch >= 0xd800 && ch <= 0xdbff) {
			if (++i >= length) {
				return NULL;
			}
			ch = r_read_be16 (name + i * 2);
			if (ch < 0xdc00 || ch > 0xdfff) {
				return NULL;
			}
		}
	}
	char buffer[1024];
	int bytes = r_str_utf16_to_utf8 ((ut8 *)buffer, sizeof (buffer) - 1, name, length * 2, true);
	if (bytes < 1) {
		return NULL;
	}
	buffer[bytes] = 0;
	return strdup (buffer);
}

static void hfs_entry_free(void *ptr) {
	HfsEntry *entry = ptr;
	free (entry->name);
	free (entry);
}

static void hfs_children_free(HtUPKv *kv) {
	r_list_free (kv->value);
}

static bool hfs_add_entry(HfsFS *fs, HfsEntry *entry) {
	if (ht_up_find (fs->ids, entry->id, NULL)) {
		hfs_entry_free (entry);
		return false;
	}
	if (!r_list_append (fs->entries, entry)) {
		hfs_entry_free (entry);
		return false;
	}
	if (!ht_up_insert (fs->ids, entry->id, entry)) {
		return false;
	}
	if (!(entry->flags & R_FS_FILE_DELETED) && !ht_up_insert (fs->live, entry->cnid, entry)) {
		return false;
	}
	RList *children = ht_up_find (fs->children, entry->parent, NULL);
	if (!children) {
		children = r_list_new ();
		if (!children || !ht_up_insert (fs->children, entry->parent, children)) {
			r_list_free (children);
			return false;
		}
	}
	return r_list_append (children, entry) != NULL;
}

static int hfs_catalog_record(HfsFS *fs, const ut8 *record, ut32 length, ut64 location, bool live) {
	if (length < 10) {
		return 0;
	}
	ut32 key = r_read_be16 (record), namesize = r_read_be16 (record + 6);
	if (key < 6 || key > 516 || key != 6 + namesize * 2 || key + 4 > length) {
		return 0;
	}
	const ut8 *value = record + key + 2;
	ut32 type = r_read_be16 (value), size = type == 1? 88: type == 2? 248: 0;
	if ((type == 3 || type == 4) && !namesize && length - key - 2 >= 10) {
		ut32 name_length = r_read_be16 (value + 8);
		return name_length <= 255 && name_length * 2 <= length - key - 12? key + 12 + name_length * 2: 0;
	}
	if (!size || size > length - key - 2 || !namesize || namesize > 255) {
		return 0;
	}
	ut32 cnid = r_read_be32 (value + 8), parent = r_read_be32 (record + 2);
	ut16 mode = r_read_be16 (value + 42), kind = mode & 0170000;
	if ((cnid != 2 && cnid < 16) || !parent || parent == cnid || (cnid == 2 && (type != 1 || parent != 1))
			|| (type == 2 && (r_read_be32 (value + 4) || r_read_be32 (value + 84)))
			|| (type == 1 && kind && kind != 0040000)
			|| (type == 2 && kind && kind != 0100000 && kind != 0120000 && kind != 0010000
				&& kind != 0020000 && kind != 0060000 && kind != 0140000)) {
		return 0;
	}
	char *name = hfs_name (record + 8, namesize);
	bool inferred = false;
	if (!name && live) {
		name = r_str_newf ("cnid-%u", cnid);
		inferred = true;
	}
	if (!name) {
		return 0;
	}
	HfsEntry *entry = R_NEW0 (HfsEntry);
	entry->id = live? cnid: HFS_DELETED_ID | location;
	entry->cnid = cnid;
	entry->parent = parent;
	entry->mode = mode;
	entry->uid = r_read_be32 (value + 32);
	entry->gid = r_read_be32 (value + 36);
	ut32 date = r_read_be32 (value + 16);
	entry->time = date >= 2082844800U? date - 2082844800U: 0;
	entry->type = type == 1? 'd': kind == 0120000? 'l': kind && kind != 0100000? 's': 'f';
	entry->flags = live? inferred? R_FS_FILE_HEURISTIC: 0: R_FS_FILE_DELETED | R_FS_FILE_HEURISTIC;
	entry->name = name;
	entry->compressed = value[41] & 0x20;
	bool complete = true;
	if (type == 2) {
		memcpy (entry->data, value + 88, sizeof (entry->data));
		memcpy (entry->resource, value + 168, sizeof (entry->resource));
		entry->size = r_read_be64 (entry->data);
		unsigned fork_type;
		for (fork_type = 0; fork_type < 2; fork_type++) {
			HfsFork fork = {0};
			hfs_fork_init (fs, &fork, fork_type? entry->resource: entry->data);
			hfs_fork_complete (fs, &fork, cnid, fork_type? 255: 0, !live);
			if (live) {
				complete &= hfs_claim_fork (fs, &fork);
			}
			if (fork.status != R_FS_WALK_COMPLETE) {
				entry->flags |= R_FS_FILE_PARTIAL;
			}
			hfs_fork_fini (&fork);
		}
	}
	if (!hfs_add_entry (fs, entry)) {
		complete = false;
	}
	if (live) {
		fs->owners_complete &= complete;
	}
	return key + 2 + size;
}

static int hfs_attribute_record(HfsFS *fs, const ut8 *record, ut32 length, ut64 location, bool live) {
	if (length < 18) {
		return 0;
	}
	ut32 key = r_read_be16 (record) + 2;
	ut32 namesize = (ut32)r_read_be16 (record + 12) * 2, cnid = r_read_be32 (record + 4);
	ut32 start = r_read_be32 (record + 8);
	if (key < 14 || (key & 1) || key > length - 4 || r_read_be16 (record + 2) || !cnid
			|| namesize != key - 14 || namesize > sizeof (fs->attribute_name)) {
		return 0;
	}
	const ut8 *value = record + key;
	ut32 type = r_read_be32 (value);
	if (type != 0x30) {
		if (fs->attribute_open && fs->attribute_next != fs->attribute_blocks) {
			fs->owners_complete = false;
		}
		fs->attribute_open = false;
		if (start) {
			return 0;
		}
	}
	if (type == 0x10) {
		return length - key >= 16 && r_read_be32 (value + 12) <= length - key - 16? length: 0;
	}
	if (type != 0x20 && type != 0x30) {
		return 0;
	}
	ut32 minimum = type == 0x20? 88: 72;
	if (minimum > length - key) {
		return 0;
	}
	HfsFork fork = {0};
	if (type == 0x20) {
		hfs_fork_init (fs, &fork, value + 8);
		fs->attribute_file = cnid;
		fs->attribute_blocks = fork.blocks;
		fs->attribute_next = 0;
		fs->attribute_name_size = namesize;
		memcpy (fs->attribute_name, record + 14, namesize);
		fs->attribute_open = true;
	} else {
		if (!fs->attribute_open || cnid != fs->attribute_file || start != fs->attribute_next
				|| namesize != fs->attribute_name_size || memcmp (fs->attribute_name, record + 14, namesize)) {
			return 0;
		}
		fork.blocks = fs->attribute_blocks - fs->attribute_next;
		fork.status = hfs_extents_add (fs, &fork, value + 8)? R_FS_WALK_COMPLETE: R_FS_WALK_ERROR;
	}
	HfsRun *last = RVecHfsRun_last (&fork.runs);
	ut64 blocks = last? (last->logical + last->size) / fs->block_size: 0;
	bool valid = hfs_claim_fork (fs, &fork) && (type == 0x20 || blocks);
	fs->attribute_next += blocks;
	hfs_fork_fini (&fork);
	return valid? length: 0;
}

static int hfs_entry_compare(const void *a, const void *b) {
	const HfsEntry *left = a, *right = b;
	int result = r_str_casecmp (left->name, right->name);
	return result? result: strcmp (left->name, right->name);
}

static bool hfs_sort_children(void *user, const ut64 id, const void *value) {
	r_list_sort ((RList *)value, hfs_entry_compare);
	return true;
}

static bool hfs_journal(HfsFS *fs) {
	if (!(fs->volume_flags & (1 << 13))) {
		return true;
	}
	ut8 info[52], header[44];
	ut64 info_offset = (ut64)fs->journal * fs->block_size;
	if (!fs->journal || !hfs_claim (fs, info_offset, fs->block_size, false)
			|| !hfs_disk (fs, info_offset, info, sizeof (info))) {
		return false;
	}
	ut32 flags = r_read_be32 (info);
	ut64 offset = r_read_be64 (info + 36), size = r_read_be64 (info + 44);
	if (flags != 1 || size < sizeof (header) || !hfs_claim (fs, offset, size, false)
			|| !hfs_disk (fs, offset, header, sizeof (header))) {
		return false;
	}
	bool big = r_read_be32 (header + 4) == 0x12345678;
	ut32 magic = big? r_read_be32 (header): r_read_le32 (header);
	ut32 endian = big? r_read_be32 (header + 4): r_read_le32 (header + 4);
	ut64 start = big? r_read_be64 (header + 8): r_read_le64 (header + 8);
	ut64 end = big? r_read_be64 (header + 16): r_read_le64 (header + 16);
	ut64 declared = big? r_read_be64 (header + 24): r_read_le64 (header + 24);
	ut32 sector = big? r_read_be32 (header + 40): r_read_le32 (header + 40);
	ut32 expected = big? r_read_be32 (header + 36): r_read_le32 (header + 36);
	memset (header + 36, 0, 4);
	ut32 checksum = 0;
	unsigned i;
	for (i = 0; i < sizeof (header); i++) {
		checksum = (checksum << 8) ^ (checksum + header[i]);
	}
	return magic == 0x4a4e4c78 && endian == 0x12345678 && sector >= 512 && !(sector & (sector - 1))
		&& sector <= size && declared == size && start >= sector && start < size && start == end && ~checksum == expected;
}

static void hfs_prepare(HfsFS *fs) {
	if (fs->ready) {
		return;
	}
	fs->ready = true;
	fs->entries = r_list_newf (hfs_entry_free);
	fs->ids = ht_up_new0 ();
	fs->live = ht_up_new0 ();
	fs->children = ht_up_new (NULL, hfs_children_free, NULL);
	fs->owners_complete = (fs->volume_flags & (1 << 8)) && !(fs->volume_flags & (1 << 11));
	if (!fs->entries || !fs->ids || !fs->live || !fs->children) {
		fs->owners_complete = false;
		return;
	}
	fs->owners_complete &= hfs_claim (fs, 0, 1536, false);
	fs->owners_complete &= hfs_claim (fs, fs->size - 1024, 1024, false);
	hfs_fork_complete (fs, &fs->overflow.fork, 3, 0, false);
	fs->owners_complete &= hfs_claim_fork (fs, &fs->overflow.fork);
	if (hfs_tree_init (fs, &fs->overflow)) {
		fs->owners_complete &= hfs_tree_scan (fs, &fs->overflow, hfs_overflow_record, true);
	} else {
		fs->owners_complete = false;
	}
	RVecHfsOverflow_sort (&fs->extra, hfs_overflow_compare);
	hfs_fork_complete (fs, &fs->bitmap, 6, 0, false);
	hfs_fork_complete (fs, &fs->catalog.fork, 4, 0, false);
	hfs_fork_complete (fs, &fs->attributes.fork, 8, 0, false);
	hfs_fork_complete (fs, &fs->startup, 7, 0, false);
	fs->owners_complete &= hfs_claim_fork (fs, &fs->bitmap);
	fs->owners_complete &= hfs_claim_fork (fs, &fs->catalog.fork);
	fs->owners_complete &= hfs_claim_fork (fs, &fs->attributes.fork);
	fs->owners_complete &= hfs_claim_fork (fs, &fs->startup);
	if (hfs_tree_init (fs, &fs->catalog)) {
		ut8 comparison;
		if (fs->case_sensitive && (!hfs_fork_read (fs, &fs->catalog.fork, 51, &comparison, 1)
				|| (comparison != 0xbc && comparison != 0xcf))) {
			fs->owners_complete = false;
		} else if (fs->case_sensitive) {
			fs->case_sensitive = comparison == 0xbc;
		}
		fs->owners_complete &= hfs_tree_scan (fs, &fs->catalog, hfs_catalog_record, true);
	} else {
		fs->owners_complete = false;
	}
	if (fs->attributes.fork.size || fs->attributes.fork.blocks) {
		fs->owners_complete &= hfs_tree_init (fs, &fs->attributes)
			&& hfs_tree_scan (fs, &fs->attributes, hfs_attribute_record, false);
		fs->owners_complete &= !fs->attribute_open || fs->attribute_next == fs->attribute_blocks;
	}
	fs->owners_complete &= hfs_journal (fs);
	hfs_merge_runs (&fs->owners);
	hfs_merge_runs (&fs->bad);
	ht_up_foreach (fs->children, hfs_sort_children, NULL);
	RListIter *iter;
	HfsEntry *entry;
	r_list_foreach (fs->entries, iter, entry) {
		if (entry->flags & R_FS_FILE_DELETED) {
			if (ht_up_find (fs->live, entry->cnid, NULL)) {
				entry->flags |= R_FS_FILE_CONFLICT;
			}
			if (!fs->catalog.complete) {
				entry->flags |= R_FS_FILE_PARTIAL;
			}
		}
	}
	if (!fs->owners_complete) {
		R_LOG_WARN ("Incomplete HFS+ ownership: retaining readable catalog evidence");
	}
}

static int hfs_allocated(HfsFS *fs, ut32 block) {
	ut64 byte = block / 8;
	if (byte >= fs->bitmap.size) {
		return -1;
	}
	if (!fs->bitmap_size || byte < fs->bitmap_page || byte - fs->bitmap_page >= fs->bitmap_size) {
		fs->bitmap_page = byte / sizeof (fs->bitmap_cache) * sizeof (fs->bitmap_cache);
		fs->bitmap_size = R_MIN ((ut64)sizeof (fs->bitmap_cache), fs->bitmap.size - fs->bitmap_page);
		fs->bitmap_known = hfs_fork_read (fs, &fs->bitmap, fs->bitmap_page, fs->bitmap_cache, fs->bitmap_size);
	}
	return fs->bitmap_known? (fs->bitmap_cache[byte - fs->bitmap_page] >> (7 - block % 8)) & 1: -1;
}

static bool hfs_initialize(HfsFS *fs) {
	ut8 header[512];
	ut64 address;
	if (r_add_overflow_ut64 (fs->root->delta, 1536, &address)
			|| fs->root->iob.read_at (fs->root->iob.io, fs->root->delta + 1024, header, sizeof (header)) != sizeof (header)) {
		return false;
	}
	ut64 embedded_size = UT64_MAX;
	if (r_read_be16 (header) == 0x4244) {
		ut32 block_size = r_read_be32 (header + 20), start = r_read_be16 (header + 28);
		if ((r_read_be16 (header + 124) != 0x482b && r_read_be16 (header + 124) != 0x4858)
				|| block_size < 512 || (block_size & (block_size - 1))) {
			return false;
		}
		fs->base = (ut64)start * 512 + (ut64)r_read_be16 (header + 126) * block_size;
		embedded_size = (ut64)r_read_be16 (header + 128) * block_size;
		if (r_add_overflow_ut64 (fs->root->delta, fs->base, &address) || address > UT64_MAX - 1536
				|| fs->root->iob.read_at (fs->root->iob.io, address + 1024, header, sizeof (header)) != sizeof (header)) {
			return false;
		}
	}
	ut32 magic = r_read_be16 (header);
	fs->block_size = r_read_be32 (header + 40);
	if ((magic != 0x482b && magic != 0x4858) || fs->block_size < 512 || (fs->block_size & (fs->block_size - 1))) {
		return false;
	}
	fs->geometry = true;
	fs->blocks = r_read_be32 (header + 44);
	fs->size = (ut64)fs->blocks * fs->block_size;
	if ((magic == 0x482b? r_read_be16 (header + 2) != 4: r_read_be16 (header + 2) != 5)
			|| fs->size < 2048 || fs->size > embedded_size
			|| fs->root->delta > UT64_MAX - fs->base || fs->size > UT64_MAX - fs->root->delta - fs->base) {
		return false;
	}
	fs->case_sensitive = magic == 0x4858;
	fs->volume_flags = r_read_be32 (header + 4);
	fs->journal = r_read_be32 (header + 12);
	hfs_fork_init (fs, &fs->bitmap, header + 112);
	hfs_fork_init (fs, &fs->overflow.fork, header + 192);
	hfs_fork_init (fs, &fs->catalog.fork, header + 272);
	hfs_fork_init (fs, &fs->attributes.fork, header + 352);
	hfs_fork_init (fs, &fs->startup, header + 432);
	return true;
}

static ut64 hfs_lookup(HfsFS *fs, const char *path) {
	hfs_prepare (fs);
	char *copy = strdup (path), *state = NULL;
	if (!copy) {
		return UT64_MAX;
	}
	ut64 id = 2;
	char *part = r_str_tok_r (copy, "/", &state);
	while (part) {
		HfsEntry *directory = ht_up_find (fs->live, id, NULL);
		if (!directory || directory->type != 'd') {
			id = UT64_MAX;
			break;
		}
		if (!strcmp (part, ".") || !strcmp (part, "..")) {
			if (!strcmp (part, "..") && id != 2) {
				id = directory->parent;
			}
			part = r_str_tok_r (NULL, "/", &state);
			continue;
		}
		RList *children = ht_up_find (fs->children, id, NULL);
		RListIter *iter;
		HfsEntry *entry;
		ut64 found = UT64_MAX;
		bool exact = false, ambiguous = false;
		r_list_foreach (children, iter, entry) {
			bool matches = !strcmp (part, entry->name);
			if ((entry->flags & R_FS_FILE_DELETED) || (!matches && (fs->case_sensitive || r_str_casecmp (part, entry->name)))) {
				continue;
			}
			if (exact && !matches) {
				continue;
			}
			if (matches && !exact) {
				found = entry->id;
				exact = true;
				ambiguous = false;
			} else {
				ambiguous |= found != UT64_MAX && found != entry->id;
				found = entry->id;
			}
		}
		id = ambiguous? UT64_MAX: found;
		if (id == UT64_MAX) {
			break;
		}
		part = r_str_tok_r (NULL, "/", &state);
	}
	free (copy);
	return id;
}

static ut64 hfs_duplicate_limit(HfsFork *fork) {
	RVecHfsRun sorted = {0};
	ut64 limit = UT64_MAX;
	size_t i;
	for (i = 0; i < RVecHfsRun_length (&fork->runs); i++) {
		HfsRun *copy = RVecHfsRun_emplace_back (&sorted);
		if (!copy) {
			limit = 0;
			goto done;
		}
		*copy = *RVecHfsRun_at (&fork->runs, i);
	}
	RVecHfsRun_sort (&sorted, hfs_physical_compare);
	ut64 end = 0, first = 0;
	for (i = 0; i < RVecHfsRun_length (&sorted); i++) {
		HfsRun *run = RVecHfsRun_at (&sorted, i);
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
	RVecHfsRun_fini (&sorted);
	return limit;
}

static int hfs_emit_range(RFSRange *run, const RFSRange *next, RFSRangeCb callback, void *user) {
	if (run->size && (run->flags != next->flags || run->logical + run->size != next->logical
			|| run->physical + run->size != next->physical)) {
		if (!callback (run, user)) {
			return R_FS_WALK_STOPPED;
		}
		run->size = 0;
	}
	if (run->size) {
		run->size += next->size;
	} else {
		*run = *next;
	}
	return R_FS_WALK_COMPLETE;
}

static int FSP(_forensic_extents)(RFSFile *file, RFSRangeCb callback, void *user) {
	HfsFile *handle = file->ptr;
	HfsFS *fs = handle->fs;
	if (!fs->native || handle->grub || (file->type != 'f' && file->type != 'l') || handle->entry->compressed) {
		return R_FS_WALK_UNSUPPORTED;
	}
	ut64 limit = file->size, logical = 0, readable = UT64_MAX;
	int status = handle->data.status;
	if (handle->recovery) {
		if (!(file->flags & R_FS_FILE_DELETED) || !fs->owners_complete || (file->flags & R_FS_FILE_CONFLICT)) {
			file->flags |= R_FS_FILE_PARTIAL;
			handle->readable = 0;
			handle->planned = true;
			return R_FS_WALK_ERROR;
		}
		ut64 duplicate = hfs_duplicate_limit (&handle->data);
		if (duplicate < limit) {
			limit = duplicate;
			status = R_FS_WALK_ERROR;
			file->flags |= R_FS_FILE_CONFLICT;
		}
	}
	RFSRange run = {0};
	while (logical < limit) {
		HfsRun *mapping = hfs_run_at (&handle->data.runs, logical);
		if (!mapping) {
			status = R_FS_WALK_ERROR;
			break;
		}
		ut64 physical = mapping->physical + logical - mapping->logical;
		ut64 size = R_MIN (mapping->size - (logical - mapping->logical), limit - logical);
		size = R_MIN (size, fs->block_size - physical % fs->block_size);
		int allocated = hfs_allocated (fs, physical / fs->block_size);
		bool owned = handle->recovery && hfs_run_at (&fs->owners, physical);
		if (handle->recovery && (allocated != 0 || owned)) {
			status = R_FS_WALK_ERROR;
			if (allocated > 0 || owned) {
				file->flags |= R_FS_FILE_CONFLICT;
			}
			if (!handle->salvage) {
				break;
			}
			readable = R_MIN (readable, logical);
			logical += size;
			continue;
		}
		ut32 flags = allocated < 0? R_FS_RANGE_UNKNOWN: allocated? R_FS_RANGE_ALLOCATED: R_FS_RANGE_FREE;
		if (allocated < 0) {
			status = R_FS_WALK_ERROR;
		}
		RFSRange next = { logical, fs->root->delta + fs->base + physical, size, flags };
		if (hfs_emit_range (&run, &next, callback, user) == R_FS_WALK_STOPPED) {
			return R_FS_WALK_STOPPED;
		}
		logical += size;
	}
	if (run.size && !callback (&run, user)) {
		return R_FS_WALK_STOPPED;
	}
	if (handle->recovery) {
		handle->readable = R_MIN (readable, logical);
		handle->planned = true;
	}
	if (status != R_FS_WALK_COMPLETE || logical != file->size) {
		file->flags |= R_FS_FILE_PARTIAL;
		return R_FS_WALK_ERROR;
	}
	return R_FS_WALK_COMPLETE;
}

static bool hfs_accept_range(const RFSRange *range, void *user) {
	return true;
}

static RFSFile *FSP(_forensic_open_id)(RFSRoot *root, ut64 id, ut32 flags) {
	HfsFS *fs = root->ptr;
	if (!fs->native || (flags & ~(R_FS_OPEN_RECOVER | R_FS_OPEN_SALVAGE))) {
		return NULL;
	}
	hfs_prepare (fs);
	HfsEntry *entry = ht_up_find (fs->ids, id, NULL);
	if (!entry || ((flags & R_FS_OPEN_RECOVER) && !(entry->flags & R_FS_FILE_DELETED))) {
		return NULL;
	}
	RFSFile *file = r_fs_file_new (root, entry->name);
	HfsFile *handle = R_NEW0 (HfsFile);
	handle->fs = fs;
	handle->entry = entry;
	handle->recovery = flags & R_FS_OPEN_RECOVER;
	handle->salvage = handle->recovery && (flags & R_FS_OPEN_SALVAGE);
	file->ptr = handle;
	file->id = id;
	file->size = entry->size;
	file->type = entry->type;
	file->flags = entry->flags;
	file->time = entry->time;
	file->uid = entry->uid;
	file->gid = entry->gid;
	file->perm = entry->mode & 07777;
	if (entry->type != 'd') {
		hfs_fork_init (fs, &handle->data, entry->data);
		hfs_fork_complete (fs, &handle->data, entry->cnid, 0, entry->flags & R_FS_FILE_DELETED);
		HfsRun *first = RVecHfsRun_at (&handle->data.runs, 0);
		if (first) {
			file->off = root->delta + fs->base + first->physical;
		}
	}
	return file;
}

static void FSP(_forensic_close)(RFSFile *file) {
	HfsFile *handle = file->ptr;
	if (handle->grub) {
		file->ptr = handle->grub;
		FSP(_close) (file);
		grubfs_free (handle->grub);
	}
	hfs_fork_fini (&handle->data);
	free (handle);
	file->ptr = NULL;
}

static int FSP(_forensic_read)(RFSFile *file, ut64 offset, int length) {
	HfsFile *handle = file->ptr;
	if (handle->grub) {
		file->ptr = handle->grub;
		int result = FSP(_read) (file, offset, length);
		file->ptr = handle;
		return result;
	}
	if (offset >= file->size) {
		return 0;
	}
	if (handle->entry->compressed || file->type == 'd') {
		return -1;
	}
	ut64 readable = file->size;
	if (file->flags & R_FS_FILE_DELETED) {
		if (!handle->planned) {
			bool recovery = handle->recovery;
			handle->recovery = true;
			FSP(_forensic_extents) (file, hfs_accept_range, NULL);
			handle->recovery = recovery;
		}
		readable = handle->planned? handle->readable: 0;
	}
	if (offset >= readable) {
		return -1;
	}
	length = R_MIN ((ut64)length, readable - offset);
	int done = 0;
	while (done < length) {
		HfsRun *run = hfs_run_at (&handle->data.runs, offset + done);
		if (!run) {
			file->flags |= R_FS_FILE_PARTIAL;
			break;
		}
		int chunk = R_MIN ((ut64)(length - done), run->size - (offset + done - run->logical));
		if (!hfs_fork_read (handle->fs, &handle->data, offset + done, file->data + done, chunk)) {
			file->flags |= R_FS_FILE_PARTIAL;
			break;
		}
		done += chunk;
	}
	return done? done: -1;
}

static RFSFile *FSP(_forensic_open)(RFSRoot *root, const char *path, bool create) {
	HfsFS *fs = root->ptr;
	ut64 id = fs->native? hfs_lookup (fs, path): UT64_MAX;
	RFSFile *native = id != UT64_MAX? FSP(_forensic_open_id) (root, id, 0): NULL;
	if (native && native->type == 'f' && !((HfsFile *)native->ptr)->entry->compressed) {
		RFSFile *file = r_fs_file_new (root, path);
		file->ptr = native->ptr;
		file->id = native->id;
		file->off = native->off;
		file->size = native->size;
		file->type = native->type;
		file->flags = native->flags;
		file->time = native->time;
		file->uid = native->uid;
		file->gid = native->gid;
		file->perm = native->perm;
		r_fs_file_free (native);
		return file;
	}
	if (native) {
		FSP(_forensic_close) (native);
		r_fs_file_free (native);
	}
	RFSFile *file = FSP(_open) (root, path, create);
	if (file) {
		HfsFile *handle = R_NEW0 (HfsFile);
		handle->fs = fs;
		handle->grub = file->ptr;
		file->ptr = handle;
	}
	return file;
}

static RList *FSP(_forensic_dir)(RFSRoot *root, const char *path, ut64 id, int view) {
	HfsFS *fs = root->ptr;
	if (!fs->native) {
		if (!(view & (R_FS_VIEW_NORMAL | R_FS_VIEW_SPECIAL))) {
			return NULL;
		}
		root->ptr = fs->grub;
		RList *result = FSP(_dir) (root, path, id, view);
		root->ptr = fs;
		return result;
	}
	hfs_prepare (fs);
	bool carve = !id && (view & R_FS_VIEW_DELETED);
	ut64 parent = id == UT64_MAX? hfs_lookup (fs, path): id;
	HfsEntry *directory = ht_up_find (fs->ids, parent, NULL);
	if (!carve && (!directory || directory->type != 'd')) {
		return NULL;
	}
	RList *children = carve? fs->entries: ht_up_find (fs->children, directory->cnid, NULL);
	RList *result = r_list_newf ((RListFree)r_fs_file_free);
	RListIter *iter;
	HfsEntry *entry;
	r_list_foreach (children, iter, entry) {
		bool deleted = entry->flags & R_FS_FILE_DELETED;
		if ((carve && !deleted) || !(view & (deleted? R_FS_VIEW_DELETED: R_FS_VIEW_NORMAL | R_FS_VIEW_SPECIAL))) {
			continue;
		}
		RFSFile *file = r_fs_file_new (root, entry->name);
		file->id = entry->id;
		file->size = entry->size;
		file->time = entry->time;
		file->type = entry->type;
		file->flags = entry->flags;
		r_list_append (result, file);
	}
	return result;
}

static int FSP(_forensic_ranges)(RFSRoot *root, ut32 flags, RFSRangeCb callback, void *user) {
	HfsFS *fs = root->ptr;
	if (!fs->native || !flags || (flags & ~(R_FS_RANGE_FREE | R_FS_RANGE_ALLOCATED | R_FS_RANGE_ORPHAN | R_FS_RANGE_BAD | R_FS_RANGE_UNKNOWN))) {
		return R_FS_WALK_UNSUPPORTED;
	}
	hfs_prepare (fs);
	if ((flags & R_FS_RANGE_ORPHAN) && !fs->owners_complete) {
		return R_FS_WALK_ERROR;
	}
	int status = R_FS_WALK_COMPLETE;
	RFSRange run = {0};
	ut64 block;
	for (block = 0; block < fs->blocks; block++) {
		ut64 offset = block * fs->block_size;
		int allocated = hfs_allocated (fs, block);
		ut32 state = allocated < 0? R_FS_RANGE_UNKNOWN: allocated? R_FS_RANGE_ALLOCATED: R_FS_RANGE_FREE;
		if (allocated < 0) {
			status = R_FS_WALK_ERROR;
		}
		if (hfs_run_at (&fs->bad, offset)) {
			state = R_FS_RANGE_BAD;
		} else if ((flags & R_FS_RANGE_ORPHAN) && allocated > 0 && !hfs_run_at (&fs->owners, offset)) {
			state |= R_FS_RANGE_ORPHAN;
		}
		if (!(state & flags)) {
			if (run.size && !callback (&run, user)) {
				return R_FS_WALK_STOPPED;
			}
			run.size = 0;
			continue;
		}
		RFSRange next = { offset, root->delta + fs->base + offset, fs->block_size, state };
		if (hfs_emit_range (&run, &next, callback, user) == R_FS_WALK_STOPPED) {
			return R_FS_WALK_STOPPED;
		}
	}
	return run.size && !callback (&run, user)? R_FS_WALK_STOPPED: status;
}

static bool FSP(_forensic_mount)(RFSRoot *root) {
	HfsFS *fs = R_NEW0 (HfsFS);
	fs->root = root;
	fs->native = hfs_initialize (fs);
	bool mounted = false;
	if (fs->native) {
		fs->grub = grubfs_new (&FSIPTR, &root->iob);
		fs->native = fs->grub != NULL;
	} else if (fs->geometry) {
		mounted = FSP(_mount) (root);
		fs->grub = root->ptr;
	}
	root->ptr = fs;
	return fs->native || mounted;
}

static void hfs_tree_fini(HfsTree *tree) {
	hfs_fork_fini (&tree->fork);
	r_bitset_free (tree->allocated);
	r_bitset_free (tree->visited);
	r_bitset_free (tree->map_nodes);
}

static void FSP(_forensic_umount)(RFSRoot *root) {
	HfsFS *fs = root->ptr;
	if (!fs) {
		return;
	}
	root->ptr = fs->grub;
	FSP(_umount) (root);
	hfs_fork_fini (&fs->bitmap);
	hfs_fork_fini (&fs->startup);
	hfs_tree_fini (&fs->catalog);
	hfs_tree_fini (&fs->overflow);
	hfs_tree_fini (&fs->attributes);
	RVecHfsOverflow_fini (&fs->extra);
	RVecHfsRun_fini (&fs->owners);
	RVecHfsRun_fini (&fs->bad);
	ht_up_free (fs->ids);
	ht_up_free (fs->live);
	ht_up_free (fs->children);
	r_list_free (fs->entries);
	free (fs);
}
