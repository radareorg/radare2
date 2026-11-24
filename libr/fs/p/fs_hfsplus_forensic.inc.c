/* radare - LGPL - Copyright 2026 - pancake */

#include <r_vec.h>
#include "fs_hfsplus_unicode.inc.c"

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

typedef struct hfs_entry_t HfsEntry;
typedef struct hfs_stream_t HfsStream;

struct hfs_entry_t {
	ut64 id, size, time, parent_id;
	ut32 cnid, parent, flags, uid, gid, created, link_ref;
	ut16 mode;
	ut8 link_kind, private_kind, color;
	char type;
	char *name, *key;
	HfsFork data, resource;
	HfsEntry *target;
	RList *streams;
	bool compressed, inferred, thread_only, cycle;
};

struct hfs_stream_t {
	ut64 id;
	ut32 cnid, flags;
	HfsEntry *entry;
	char *name;
	HfsFork data;
	bool resource, resident;
};

typedef struct {
	ut64 location;
	ut32 cnid, parent;
	char *name;
	bool live, directory;
} HfsThread;

typedef struct {
	ut64 location;
	ut32 cnid, start, type;
	char *name;
	HfsFork data;
	ut8 extents[64];
	bool live;
} HfsAttribute;
R_VEC_TYPE (RVecHfsAttribute, HfsAttribute);

typedef struct {
	RFSRoot *root;
	GrubFS *grub;
	ut64 base, size;
	ut32 block_size, blocks, volume_flags, journal;
	HfsFork bitmap, startup;
	HfsTree catalog, overflow, attributes;
	RVecHfsOverflow extra;
	RVecHfsRun owners, bad;
	RList *entries, *threads, *streams;
	HtUP *ids, *live, *children, *directories, *thread_index, *stream_ids, *versions, *inodes;
	RVecHfsAttribute attrs;
	ut64 next_stream;
	ut64 bitmap_page;
	ut32 bitmap_size;
	ut8 bitmap_cache[4096];
	bool bitmap_known, geometry, native, case_sensitive, ready, owners_complete;
} HfsFS;

typedef struct {
	HfsFS *fs;
	GrubFS *grub;
	HfsFork *data;
	HfsStream *stream;
	HfsEntry *source;
	ut64 readable;
	bool recovery, salvage, planned, blocked;
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

static ut32 hfs_unicode_value(const HfsUnicode *table, size_t count, ut32 code, ut32 fallback) {
	size_t low = 0, high = count;
	while (low < high) {
		size_t mid = low + (high - low) / 2;
		if (table[mid].code < code) {
			low = mid + 1;
		} else {
			high = mid;
		}
	}
	return low < count && table[low].code == code? table[low].value: fallback;
}

static char *hfs_name_key(const char *name, bool sensitive) {
	ut32 characters[1024], count = 0;
	size_t length = strlen (name), position = 0;
	if (length > 4096) {
		return NULL;
	}
	while (position < length) {
		RRune code;
		int size = r_utf8_decode ((const ut8 *)name + position, length - position, &code);
		if (!size) {
			return NULL;
		}
		if (code == '%' && length - position >= 3 && IS_HEXCHAR (name[position + 1]) && IS_HEXCHAR (name[position + 2])) {
			ut8 byte = 0;
			r_hex_to_byte (&byte, name[position + 1]);
			r_hex_to_byte (&byte, name[position + 2]);
			code = byte;
			size = 3;
		}
		position += size;
		ut32 hangul[3], values = 1;
		const ut32 *decomposed = &code;
		ut32 mapping = hfs_unicode_value (hfs_decomposition, R_ARRAY_SIZE (hfs_decomposition), code, UT32_MAX);
		if (code >= 0xac00 && code < 0xd7a4) {
			ut32 syllable = code - 0xac00;
			hangul[0] = 0x1100 + syllable / 588;
			hangul[1] = 0x1161 + (syllable % 588) / 28;
			hangul[2] = 0x11a7 + syllable % 28;
			values = syllable % 28? 3: 2;
			decomposed = hangul;
		} else if (mapping != UT32_MAX) {
			values = mapping & 7;
			decomposed = hfs_decomposed + (mapping >> 3);
		}
		ut32 i;
		for (i = 0; i < values; i++) {
			if (count == R_ARRAY_SIZE (characters)) {
				return NULL;
			}
			ut32 ch = decomposed[i], at = count++;
			ut32 category = hfs_unicode_value (hfs_combining, R_ARRAY_SIZE (hfs_combining), ch, 0);
			while (category && at && hfs_unicode_value (hfs_combining, R_ARRAY_SIZE (hfs_combining), characters[at - 1], 0) > category) {
				characters[at] = characters[at - 1];
				at--;
			}
			characters[at] = ch;
		}
	}
	ut8 buffer[4097];
	ut32 i, bytes = 0;
	for (i = 0; i < count; i++) {
		ut32 ch = characters[i];
		if (!sensitive) {
			ch = hfs_unicode_value (hfs_fold, R_ARRAY_SIZE (hfs_fold), ch, ch);
			if (!ch) {
				continue;
			}
		}
		if (!ch) {
			buffer[bytes++] = 255;
		} else {
			bytes += r_utf8_encode (buffer + bytes, ch);
		}
	}
	buffer[bytes] = 0;
	return strdup ((const char *)buffer);
}

static char *hfs_name(const ut8 *name, ut32 length) {
	if (!length || length > 255) {
		return NULL;
	}
	char buffer[2048];
	ut32 i, bytes = 0;
	for (i = 0; i < length; i++) {
		ut32 code = r_read_be16 (name + i * 2);
		if (code >= 0xdc00 && code <= 0xdfff) {
			return NULL;
		}
		if (code >= 0xd800 && code <= 0xdbff) {
			if (++i >= length) {
				return NULL;
			}
			ut32 low = r_read_be16 (name + i * 2);
			if (low < 0xdc00 || low > 0xdfff) {
				return NULL;
			}
			code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
		}
		if (code < 32 || code == 127 || code == '/' || code == '%') {
			bytes += snprintf (buffer + bytes, sizeof (buffer) - bytes, "%%%02X", code);
		} else {
			bytes += r_utf8_encode ((ut8 *)buffer + bytes, code);
		}
	}
	buffer[bytes] = 0;
	return strdup (buffer);
}

static void hfs_entry_free(void *ptr) {
	HfsEntry *entry = ptr;
	free (entry->name);
	free (entry->key);
	hfs_fork_fini (&entry->data);
	hfs_fork_fini (&entry->resource);
	r_list_free (entry->streams);
	free (entry);
}

static void hfs_children_free(HtUPKv *kv) {
	r_list_free (kv->value);
}

static bool hfs_bucket_append(HtUP *index, ut64 id, void *entry) {
	RList *bucket = ht_up_find (index, id, NULL);
	if (!bucket) {
		bucket = r_list_new ();
		if (!bucket || !ht_up_insert (index, id, bucket)) {
			r_list_free (bucket);
			return false;
		}
	}
	return r_list_append (bucket, entry) != NULL;
}

static bool hfs_add_entry(HfsFS *fs, HfsEntry *entry) {
	entry->key = hfs_name_key (entry->name, fs->case_sensitive);
	entry->streams = r_list_new ();
	entry->parent_id = UT64_MAX;
	if (!entry->key || !entry->streams || ht_up_find (fs->ids, entry->id, NULL)
			|| !r_list_append (fs->entries, entry)) {
		hfs_entry_free (entry);
		return false;
	}
	if (!ht_up_insert (fs->ids, entry->id, entry)) {
		return false;
	}
	if (!(entry->flags & R_FS_FILE_DELETED) && !ht_up_insert (fs->live, entry->cnid, entry)) {
		return false;
	}
	return hfs_bucket_append (fs->versions, entry->cnid, entry)
		&& (entry->type != 'd' || hfs_bucket_append (fs->directories, entry->cnid, entry));
}

static void hfs_stream_free(void *ptr) {
	HfsStream *stream = ptr;
	free (stream->name);
	hfs_fork_fini (&stream->data);
	free (stream);
}

static HfsStream *hfs_add_stream(HfsFS *fs, HfsEntry *entry, ut32 cnid, const char *name, ut32 flags) {
	HfsStream *stream = R_NEW0 (HfsStream);
	stream->id = fs->next_stream++;
	stream->entry = entry;
	stream->cnid = cnid;
	stream->flags = flags;
	stream->name = strdup (name);
	if (!stream->name || stream->id >= HFS_DELETED_ID || !r_list_append (fs->streams, stream)) {
		hfs_stream_free (stream);
		return NULL;
	}
	if (!ht_up_insert (fs->stream_ids, stream->id, stream)
			|| (entry && !r_list_append (entry->streams, stream))) {
		fs->owners_complete = false;
		return NULL;
	}
	return stream;
}

static void hfs_thread_free(void *ptr) {
	HfsThread *thread = ptr;
	free (thread->name);
	free (thread);
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
		if (name_length > 255 || name_length * 2 > length - key - 12 || r_read_be16 (value + 2)) {
			return 0;
		}
		char *name = hfs_name (value + 10, name_length);
		if (!name) {
			return 0;
		}
		HfsThread *thread = R_NEW0 (HfsThread);
		*thread = (HfsThread){ .location = location, .cnid = r_read_be32 (record + 2),
			.parent = r_read_be32 (value + 4), .name = name, .live = live, .directory = type == 3 };
		if (!r_list_append (fs->threads, thread)) {
			hfs_thread_free (thread);
			return 0;
		}
		if (!hfs_bucket_append (fs->thread_index, thread->cnid, thread)) {
			return 0;
		}
		return key + 12 + name_length * 2;
	}
	if (!size || size > length - key - 2 || !namesize || namesize > 255) {
		return 0;
	}
	ut32 cnid = r_read_be32 (value + 8), parent = r_read_be32 (record + 2);
	ut16 mode = r_read_be16 (value + 42), kind = mode & 0170000;
	if ((cnid != 2 && cnid < 16) || !parent || parent == cnid || (cnid == 2 && (type != 1 || parent != 1))
			|| (type == 2 && ((r_read_be32 (value + 4) && !(r_read_be16 (value + 2) & 0x20)) || r_read_be32 (value + 84)))
			|| (type == 1 && kind && kind != 0040000)
			|| (type == 2 && kind && kind != 0100000 && kind != 0120000 && kind != 0010000
				&& kind != 0020000 && kind != 0060000 && kind != 0140000)) {
		return 0;
	}
	char *name = hfs_name (record + 8, namesize);
	bool inferred = false;
	if (!name) {
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
	entry->created = r_read_be32 (value + 12);
	entry->uid = r_read_be32 (value + 32);
	entry->gid = r_read_be32 (value + 36);
	ut32 date = r_read_be32 (value + 16);
	entry->time = date >= 2082844800U? date - 2082844800U: 0;
	entry->type = type == 1? 'd': kind == 0120000? 'l': kind && kind != 0100000? 's': 'f';
	entry->flags = live? inferred? R_FS_FILE_HEURISTIC: 0: R_FS_FILE_DELETED | R_FS_FILE_HEURISTIC;
	entry->name = name;
	entry->inferred = inferred;
	entry->compressed = value[41] & 0x20;
	bool complete = true;
	if (type == 1 && parent == 2) {
		if (!strcmp (name, "%00%00%00%00HFS+ Private Data")
				|| !strcmp (name, "\xe2\x90\x80\xe2\x90\x80\xe2\x90\x80\xe2\x90\x80HFS+ Private Data")) {
			entry->private_kind = 1;
		} else if (!strcmp (name, ".HFS+ Private Directory Data%0D")) {
			entry->private_kind = 2;
		}
	}
	if (type == 2) {
		ut32 file_type = r_read_be32 (value + 48), creator = r_read_be32 (value + 52);
		if (file_type == 0x686c6e6b && creator == 0x6866732b) {
			entry->link_kind = 1;
		} else if (file_type == 0x66647270 && creator == 0x4d414353 && (r_read_be16 (value + 2) & 0x20)) {
			entry->link_kind = 2;
		}
		entry->link_ref = r_read_be32 (value + 44);
		hfs_fork_init (fs, &entry->data, value + 88);
		hfs_fork_complete (fs, &entry->data, cnid, 0, !live);
		hfs_fork_init (fs, &entry->resource, value + 168);
		hfs_fork_complete (fs, &entry->resource, cnid, 255, !live);
		entry->size = entry->data.size;
		if (live) {
			complete &= hfs_claim_fork (fs, &entry->data);
			complete &= hfs_claim_fork (fs, &entry->resource);
		}
		if (entry->data.status != R_FS_WALK_COMPLETE || entry->resource.status != R_FS_WALK_COMPLETE) {
			entry->flags |= R_FS_FILE_PARTIAL;
		}
	}
	if (!hfs_add_entry (fs, entry)) {
		complete = false;
	} else if (type == 2 && !entry->link_kind) {
		HfsStream *resource = hfs_add_stream (fs, entry, cnid, "rsrc", entry->flags);
		if (resource) {
			resource->resource = true;
			resource->data = entry->resource;
			memset (&entry->resource, 0, sizeof (entry->resource));
		} else {
			complete = false;
		}
	}
	if (live) {
		fs->owners_complete &= complete;
	}
	return key + 2 + size;
}

static bool hfs_inline_fork(HfsFS *fs, HfsFork *fork, ut64 offset, ut32 size) {
	fork->size = size;
	fork->status = R_FS_WALK_ERROR;
	ut64 done = 0;
	while (done < size) {
		HfsRun *source = hfs_run_at (&fs->attributes.fork.runs, offset + done);
		if (!source) {
			return false;
		}
		ut64 within = offset + done - source->logical;
		HfsRun *run = RVecHfsRun_emplace_back (&fork->runs);
		if (!run) {
			return false;
		}
		*run = (HfsRun){ done, source->physical + within, R_MIN (size - done, source->size - within) };
		done += run->size;
	}
	fork->status = R_FS_WALK_COMPLETE;
	return true;
}

static int hfs_attribute_record(HfsFS *fs, const ut8 *record, ut32 length, ut64 location, bool live) {
	if (length < 18) {
		return 0;
	}
	ut32 key = r_read_be16 (record) + 2;
	ut32 namesize = (ut32)r_read_be16 (record + 12) * 2, cnid = r_read_be32 (record + 4);
	ut32 start = r_read_be32 (record + 8);
	if (key < 14 || (key & 1) || key > length - 4 || r_read_be16 (record + 2) || !cnid
			|| namesize != key - 14 || !namesize || namesize > 510) {
		return 0;
	}
	const ut8 *value = record + key;
	ut32 type = r_read_be32 (value), minimum;
	switch (type) {
	case 0x10:
		if (start || length - key < 16 || r_read_be32 (value + 12) > length - key - 16
				|| r_read_be32 (value + 4) || r_read_be32 (value + 8)) {
			return 0;
		}
		minimum = 16 + r_read_be32 (value + 12);
		break;
	case 0x20:
		if (start) {
			return 0;
		}
		minimum = 88;
		break;
	case 0x30:
		minimum = 72;
		break;
	default:
		return 0;
	}
	if (minimum > length - key || r_read_be32 (value + 4)) {
		return 0;
	}
	char *name = hfs_name (record + 14, namesize / 2);
	if (!name) {
		return 0;
	}
	HfsAttribute *attribute = RVecHfsAttribute_emplace_back (&fs->attrs);
	if (!attribute) {
		free (name);
		return 0;
	}
	*attribute = (HfsAttribute){ .location = location, .cnid = cnid, .start = start, .type = type, .name = name, .live = live };
	if (type == 0x10) {
		hfs_inline_fork (fs, &attribute->data, location + key + 16, r_read_be32 (value + 12));
	} else if (type == 0x20) {
		hfs_fork_init (fs, &attribute->data, value + 8);
	} else {
		attribute->data.blocks = fs->blocks;
		memcpy (attribute->extents, value + 8, sizeof (attribute->extents));
		attribute->data.status = hfs_extents_add (fs, &attribute->data, attribute->extents)? R_FS_WALK_COMPLETE: R_FS_WALK_ERROR;
	}
	if (live && type != 0x10) {
		fs->owners_complete &= hfs_claim_fork (fs, &attribute->data);
	}
	return key + minimum;
}

static int hfs_attribute_compare(const HfsAttribute *a, const HfsAttribute *b) {
	if (a->cnid != b->cnid) {
		return a->cnid < b->cnid? -1: 1;
	}
	int result = strcmp (a->name, b->name);
	if (result) {
		return result;
	}
	if (a->live != b->live) {
		return a->live? -1: 1;
	}
	if (a->start != b->start) {
		return a->start < b->start? -1: 1;
	}
	if (a->type != b->type) {
		return a->type < b->type? -1: 1;
	}
	return a->location < b->location? -1: a->location > b->location;
}

static void hfs_attribute_streams(HfsFS *fs) {
	RVecHfsAttribute_sort (&fs->attrs, hfs_attribute_compare);
	size_t first = 0, length = RVecHfsAttribute_length (&fs->attrs);
	while (first < length) {
		HfsAttribute *base = RVecHfsAttribute_at (&fs->attrs, first);
		size_t end = first + 1, bases = base->type != 0x30;
		while (end < length) {
			HfsAttribute *other = RVecHfsAttribute_at (&fs->attrs, end);
			if (other->cnid != base->cnid || other->live != base->live || strcmp (other->name, base->name)) {
				break;
			}
			bases += other->type != 0x30;
			end++;
		}
		HfsEntry *owner = NULL;
		RListIter *iter;
		HfsEntry *entry;
		bool ambiguous = false;
		RList *versions = ht_up_find (fs->versions, base->cnid, NULL);
		r_list_foreach (versions, iter, entry) {
			if (entry->cnid != base->cnid || (base->live && (entry->flags & R_FS_FILE_DELETED))) {
				continue;
			}
			if (owner && owner != entry) {
				ambiguous = true;
			} else {
				owner = entry;
			}
		}
		if (ambiguous) {
			owner = NULL;
		}
		size_t i;
		for (i = first; i < end; i++) {
			HfsAttribute *part = RVecHfsAttribute_at (&fs->attrs, i);
			if (part->type == 0x30) {
				continue;
			}
			ut32 flags = part->live? 0: R_FS_FILE_DELETED | R_FS_FILE_HEURISTIC;
			if (ambiguous) {
				flags |= R_FS_FILE_CONFLICT | R_FS_FILE_PARTIAL;
			}
			HfsStream *stream = hfs_add_stream (fs, owner, part->cnid, part->name, flags);
			if (!stream) {
				fs->owners_complete = false;
				continue;
			}
			stream->resident = part->type == 0x10;
			stream->data = part->data;
			memset (&part->data, 0, sizeof (part->data));
			size_t used = 1;
			if (!stream->resident) {
				HfsRun *last = RVecHfsRun_last (&stream->data.runs);
				ut64 covered = last? (last->logical + last->size) / fs->block_size: 0;
				while (stream->data.status == R_FS_WALK_COMPLETE && covered < stream->data.blocks && bases == 1) {
					size_t low = first, high = end;
					while (low < high) {
						size_t mid = low + (high - low) / 2;
						if (RVecHfsAttribute_at (&fs->attrs, mid)->start < covered) {
							low = mid + 1;
						} else {
							high = mid;
						}
					}
					HfsAttribute *found = NULL;
					size_t matches = 0;
					while (low < end) {
						HfsAttribute *next = RVecHfsAttribute_at (&fs->attrs, low++);
						if (next->start != covered) {
							break;
						}
						if (next->type != 0x30 || (found && memcmp (found->extents, next->extents, sizeof (next->extents)))) {
							found = NULL;
							break;
						}
						found = next;
						matches++;
					}
					if (!found || (part->live && matches != 1) || !hfs_extents_add (fs, &stream->data, found->extents)) {
						break;
					}
					used += matches;
					last = RVecHfsRun_last (&stream->data.runs);
					ut64 next = last? (last->logical + last->size) / fs->block_size: 0;
					if (next <= covered) {
						break;
					}
					covered = next;
				}
				if (covered != stream->data.blocks) {
					stream->data.status = R_FS_WALK_ERROR;
				}
			}
			if (part->live && used != end - first) {
				stream->data.status = R_FS_WALK_ERROR;
			}
			if (stream->data.status != R_FS_WALK_COMPLETE || (part->live && bases != 1)) {
				stream->flags |= R_FS_FILE_PARTIAL;
				if (part->live) {
					fs->owners_complete = false;
				}
			}
		}
		if (!bases && base->live) {
			fs->owners_complete = false;
		}
		first = end;
	}
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

static bool hfs_same_identity(HfsEntry *left, HfsEntry *right) {
	return left->cnid == right->cnid && left->created == right->created
		&& left->parent == right->parent && !strcmp (left->name, right->name);
}

static HfsEntry *hfs_parent(HfsFS *fs, HfsEntry *entry) {
	if (!(entry->flags & R_FS_FILE_DELETED)) {
		HfsEntry *parent = ht_up_find (fs->live, entry->parent, NULL);
		return parent && parent->type == 'd'? parent: NULL;
	}
	RList *candidates = ht_up_find (fs->directories, entry->parent, NULL);
	RListIter *iter;
	HfsEntry *parent, *found = NULL;
	r_list_foreach (candidates, iter, parent) {
		if (entry->created && parent->created && parent->created > entry->created) {
			continue;
		}
		if (found && !hfs_same_identity (found, parent)) {
			return NULL;
		}
		if (!found || !(parent->flags & R_FS_FILE_DELETED)) {
			found = parent;
		}
	}
	return found;
}

static void hfs_thread_names(HfsFS *fs) {
	RListIter *iter;
	HfsEntry *entry;
	r_list_foreach (fs->entries, iter, entry) {
		if (!entry->inferred) {
			continue;
		}
		RList *threads = ht_up_find (fs->thread_index, entry->cnid, NULL);
		RListIter *thread_iter;
		HfsThread *thread, *found = NULL;
		bool ambiguous = false;
		r_list_foreach (threads, thread_iter, thread) {
			if (thread->directory != (entry->type == 'd') || thread->live == !!(entry->flags & R_FS_FILE_DELETED)) {
				continue;
			}
			if (found && (thread->parent != found->parent || strcmp (thread->name, found->name))) {
				ambiguous = true;
			}
			found = thread;
		}
		if (found && !ambiguous) {
			char *name = strdup (found->name), *key = hfs_name_key (found->name, fs->case_sensitive);
			if (!name || !key) {
				free (name);
				free (key);
				entry->flags |= R_FS_FILE_PARTIAL;
				continue;
			}
			free (entry->name);
			free (entry->key);
			entry->name = name;
			entry->key = key;
			entry->parent = found->parent;
			entry->flags |= R_FS_FILE_HEURISTIC;
		} else {
			entry->flags |= R_FS_FILE_PARTIAL;
		}
	}
	HfsThread *thread;
	r_list_foreach (fs->threads, iter, thread) {
		if (thread->live) {
			continue;
		}
		bool found = false;
		RList *versions = ht_up_find (fs->versions, thread->cnid, NULL);
		RListIter *version_iter;
		r_list_foreach (versions, version_iter, entry) {
			if ((entry->flags & R_FS_FILE_DELETED) && entry->parent == thread->parent && !strcmp (entry->name, thread->name)) {
				found = true;
			}
		}
		if (found) {
			continue;
		}
		entry = R_NEW0 (HfsEntry);
		entry->id = HFS_DELETED_ID | thread->location;
		entry->cnid = thread->cnid;
		entry->parent = thread->parent;
		entry->type = thread->directory? 'd': 'f';
		entry->name = strdup (thread->name);
		entry->flags = R_FS_FILE_DELETED | R_FS_FILE_HEURISTIC | R_FS_FILE_PARTIAL;
		entry->thread_only = true;
		entry->data.status = R_FS_WALK_ERROR;
		if (!entry->name) {
			hfs_entry_free (entry);
		} else {
			hfs_add_entry (fs, entry);
		}
	}
}

static ut32 hfs_inode_number(const char *name) {
	ut32 value = 0;
	if (!*name || *name == '0') {
		return 0;
	}
	while (*name) {
		if (*name < '0' || *name > '9' || value > (UT32_MAX - (*name - '0')) / 10) {
			return 0;
		}
		value = value * 10 + *name++ - '0';
	}
	return value;
}

static HfsEntry *hfs_link_target(HfsFS *fs, HfsEntry *link) {
	if (!link->link_ref) {
		return NULL;
	}
	HfsEntry *root = ht_up_find (fs->live, 2, NULL), *found = NULL;
	bool deleted = link->flags & R_FS_FILE_DELETED;
	RList *candidates = ht_up_find (fs->inodes, ((ut64)link->link_kind << 32) | link->link_ref, NULL);
	RListIter *iter;
	HfsEntry *target;
	r_list_foreach (candidates, iter, target) {
		HfsEntry *directory = ht_up_find (fs->ids, target->parent_id, NULL);
		if (!directory || !link->created || (link->created != directory->created && (!root || link->created != root->created))
				|| (target->flags & R_FS_FILE_DELETED && !deleted)
				|| (directory->flags & R_FS_FILE_DELETED && !deleted)) {
			continue;
		}
		if (found && found != target) {
			return NULL;
		}
		found = target;
	}
	return found;
}

static void hfs_directory_cycles(HfsFS *fs, HfsEntry *entry, unsigned depth) {
	HfsEntry *directory = entry->target? entry->target: entry;
	if (depth > 64 || directory->color == 1) {
		entry->flags |= R_FS_FILE_CONFLICT | R_FS_FILE_PARTIAL;
		entry->cycle = true;
		entry->target = NULL;
		if (!(entry->flags & R_FS_FILE_DELETED)) {
			fs->owners_complete = false;
		}
		return;
	}
	if (directory->color == 2) {
		return;
	}
	directory->color = 1;
	RList *children = ht_up_find (fs->children, directory->id, NULL);
	RListIter *iter;
	HfsEntry *child;
	r_list_foreach (children, iter, child) {
		if (child->type == 'd' && (child->target || !child->link_kind)) {
			hfs_directory_cycles (fs, child, depth + 1);
		}
	}
	directory->color = 2;
}

static void hfs_resolve_names(HfsFS *fs) {
	hfs_thread_names (fs);
	RListIter *iter;
	HfsEntry *entry;
	r_list_foreach (fs->entries, iter, entry) {
		HfsEntry *parent = hfs_parent (fs, entry);
		if (parent) {
			entry->parent_id = parent->id;
			if (!hfs_bucket_append (fs->children, parent->id, entry)) {
				fs->owners_complete = false;
			}
		} else if (entry->cnid != 2) {
			entry->flags |= R_FS_FILE_PARTIAL | R_FS_FILE_HEURISTIC;
		}
		if ((entry->flags & R_FS_FILE_DELETED) && ht_up_find (fs->live, entry->cnid, NULL)) {
			entry->flags |= R_FS_FILE_CONFLICT;
		}
		if ((entry->flags & R_FS_FILE_DELETED) && !fs->catalog.complete) {
			entry->flags |= R_FS_FILE_PARTIAL;
		}
	}
	r_list_foreach (fs->entries, iter, entry) {
		HfsEntry *parent = ht_up_find (fs->ids, entry->parent_id, NULL);
		if (!parent || !parent->private_kind || entry->link_kind || entry->thread_only) {
			continue;
		}
		const char *prefix = parent->private_kind == 1? "iNode": "dir_";
		ut32 skip = strlen (prefix);
		ut32 ref = r_str_startswith (entry->name, prefix)? hfs_inode_number (entry->name + skip): 0;
		if (ref && (entry->type == 'd') == (parent->private_kind == 2)
				&& (parent->private_kind != 2 || ref == entry->cnid)) {
			if (!hfs_bucket_append (fs->inodes, ((ut64)parent->private_kind << 32) | ref, entry)) {
				fs->owners_complete = false;
			}
		}
	}
	r_list_foreach (fs->entries, iter, entry) {
		if (!entry->link_kind) {
			continue;
		}
		entry->target = hfs_link_target (fs, entry);
		if (!entry->target) {
			entry->flags |= R_FS_FILE_PARTIAL;
			if (!(entry->flags & R_FS_FILE_DELETED)) {
				fs->owners_complete = false;
			}
			continue;
		}
		entry->type = entry->target->type;
		entry->size = entry->target->size;
		if ((entry->flags & R_FS_FILE_DELETED) && !(entry->target->flags & R_FS_FILE_DELETED)) {
			entry->flags |= R_FS_FILE_CONFLICT | R_FS_FILE_HEURISTIC;
		}
	}
	r_list_foreach (fs->entries, iter, entry) {
		if (entry->type == 'd' && (entry->target || !entry->link_kind)) {
			hfs_directory_cycles (fs, entry, 0);
		}
	}
	ht_up_foreach (fs->children, hfs_sort_children, NULL);
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
	fs->threads = r_list_newf (hfs_thread_free);
	fs->streams = r_list_newf (hfs_stream_free);
	fs->next_stream = 1ULL << 62;
	fs->ids = ht_up_new0 ();
	fs->live = ht_up_new0 ();
	fs->children = ht_up_new (NULL, hfs_children_free, NULL);
	fs->directories = ht_up_new (NULL, hfs_children_free, NULL);
	fs->thread_index = ht_up_new (NULL, hfs_children_free, NULL);
	fs->versions = ht_up_new (NULL, hfs_children_free, NULL);
	fs->inodes = ht_up_new (NULL, hfs_children_free, NULL);
	fs->stream_ids = ht_up_new0 ();
	fs->owners_complete = (fs->volume_flags & (1 << 8)) && !(fs->volume_flags & (1 << 11));
	if (!fs->entries || !fs->threads || !fs->streams || !fs->ids || !fs->live || !fs->children
			|| !fs->directories || !fs->thread_index || !fs->stream_ids || !fs->versions || !fs->inodes) {
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
			&& hfs_tree_scan (fs, &fs->attributes, hfs_attribute_record, true);
	}
	hfs_resolve_names (fs);
	hfs_attribute_streams (fs);
	fs->owners_complete &= hfs_journal (fs);
	hfs_merge_runs (&fs->owners);
	hfs_merge_runs (&fs->bad);
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
	ut64 id = 2, parents[65] = { 2 };
	ut32 depth = 0;
	char *part = r_str_tok_r (copy, "/", &state);
	while (part) {
		HfsEntry *directory = ht_up_find (fs->ids, id, NULL);
		if (!directory || directory->cycle || directory->type != 'd' || (directory->link_kind && !directory->target)) {
			id = UT64_MAX;
			break;
		}
		if (!strcmp (part, ".") || !strcmp (part, "..")) {
			if (!strcmp (part, "..") && depth) {
				id = parents[--depth];
			}
			part = r_str_tok_r (NULL, "/", &state);
			continue;
		}
		HfsEntry *source = directory->target? directory->target: directory;
		RList *children = ht_up_find (fs->children, source->id, NULL);
		RListIter *iter;
		HfsEntry *entry;
		char *key = hfs_name_key (part, fs->case_sensitive);
		ut64 found = UT64_MAX;
		bool exact = false, ambiguous = false;
		r_list_foreach (children, iter, entry) {
			bool matches = !strcmp (part, entry->name);
			if (!key || (entry->flags & R_FS_FILE_DELETED) || strcmp (key, entry->key)) {
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
		free (key);
		id = ambiguous || depth == 64? UT64_MAX: found;
		if (id == UT64_MAX) {
			break;
		}
		parents[++depth] = id;
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
	if (!fs->native || handle->grub || (file->type != 'f' && file->type != 'l') || (!handle->stream && handle->source && handle->source->compressed)) {
		return R_FS_WALK_UNSUPPORTED;
	}
	if (handle->blocked) {
		file->flags |= R_FS_FILE_PARTIAL;
		return R_FS_WALK_ERROR;
	}
	ut64 limit = file->size, logical = 0, readable = UT64_MAX;
	int status = handle->data->status;
	if (handle->recovery) {
		if (!(file->flags & R_FS_FILE_DELETED) || !fs->owners_complete || (file->flags & R_FS_FILE_CONFLICT)) {
			file->flags |= R_FS_FILE_PARTIAL;
			handle->readable = 0;
			handle->planned = true;
			return R_FS_WALK_ERROR;
		}
		ut64 duplicate = hfs_duplicate_limit (handle->data);
		if (duplicate < limit) {
			limit = duplicate;
			status = R_FS_WALK_ERROR;
			file->flags |= R_FS_FILE_CONFLICT;
		}
	}
	RFSRange run = {0};
	while (logical < limit) {
		HfsRun *mapping = hfs_run_at (&handle->data->runs, logical);
		if (!mapping) {
			status = R_FS_WALK_ERROR;
			break;
		}
		ut64 physical = mapping->physical + logical - mapping->logical;
		ut64 size = R_MIN (mapping->size - (logical - mapping->logical), limit - logical);
		size = R_MIN (size, fs->block_size - physical % fs->block_size);
		bool resident = handle->stream && handle->stream->resident;
		int allocated = resident? 1: hfs_allocated (fs, physical / fs->block_size);
		bool owned = handle->recovery && !resident && hfs_run_at (&fs->owners, physical);
		if (handle->recovery && !resident && (allocated != 0 || owned)) {
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

static ut64 hfs_fork_path(HfsFS *fs, const char *path, bool *recognized, HfsEntry **directory) {
	*recognized = false;
	*directory = NULL;
	const char *at = path, *marker = NULL;
	while ((at = strstr (at, "/..namedfork"))) {
		if (!at[12] || at[12] == '/') {
			marker = at;
		}
		at++;
	}
	if (!marker) {
		return UT64_MAX;
	}
	char *base = r_str_ndup (path, marker - path);
	ut64 id = hfs_lookup (fs, base);
	free (base);
	HfsEntry *entry = ht_up_find (fs->ids, id, NULL);
	if (!entry) {
		return UT64_MAX;
	}
	*recognized = true;
	*directory = entry;
	const char *name = marker + 12;
	if (*name == '/') {
		name++;
	}
	if (!*name) {
		return UT64_MAX;
	}
	if (!strcmp (name, "data") && entry->type != 'd') {
		return entry->id;
	}
	HfsEntry *source = entry->target? entry->target: entry;
	HfsStream *found = NULL, *stream;
	RListIter *iter;
	r_list_foreach (source->streams, iter, stream) {
		bool matches = stream->resource? !strcmp (name, "rsrc"): r_str_startswith (name, "xattr:") && !strcmp (name + 6, stream->name);
		if (matches && !(stream->flags & R_FS_FILE_DELETED)) {
			if (found) {
				return UT64_MAX;
			}
			found = stream;
		}
	}
	return found? found->id: UT64_MAX;
}

static RFSFile *FSP(_forensic_open_id)(RFSRoot *root, ut64 id, ut32 flags) {
	HfsFS *fs = root->ptr;
	if (!fs->native || (flags & ~(R_FS_OPEN_RECOVER | R_FS_OPEN_SALVAGE))) {
		return NULL;
	}
	hfs_prepare (fs);
	HfsStream *stream = ht_up_find (fs->stream_ids, id, NULL);
	HfsEntry *entry = stream? stream->entry: ht_up_find (fs->ids, id, NULL);
	if (!entry && !stream) {
		return NULL;
	}
	HfsEntry *source = entry && entry->target? entry->target: entry;
	ut32 file_flags = (stream? stream->flags: 0) | (entry? entry->flags: 0);
	if (source && source != entry) {
		file_flags |= source->flags;
	}
	if ((flags & R_FS_OPEN_RECOVER) && !(file_flags & R_FS_FILE_DELETED)) {
		return NULL;
	}
	char *name = stream? stream->resource? strdup ("rsrc"): r_str_newf ("xattr:%s", stream->name): strdup (entry->name);
	if (!name) {
		return NULL;
	}
	RFSFile *file = r_fs_file_new (root, name);
	free (name);
	HfsFile *handle = R_NEW0 (HfsFile);
	handle->fs = fs;
	handle->source = source;
	handle->stream = stream;
	handle->data = stream? &stream->data: &source->data;
	handle->blocked = entry && (entry->thread_only || (entry->link_kind && !entry->target) || entry->cycle);
	handle->recovery = flags & R_FS_OPEN_RECOVER;
	handle->salvage = handle->recovery && (flags & R_FS_OPEN_SALVAGE);
	file->ptr = handle;
	file->id = id;
	file->size = stream? stream->data.size: entry->size;
	file->type = stream? 'f': entry->type;
	file->flags = file_flags;
	if (source) {
		file->time = source->time;
		file->uid = source->uid;
		file->gid = source->gid;
		file->perm = source->mode & 07777;
	}
	HfsRun *first = RVecHfsRun_at (&handle->data->runs, 0);
	if (first) {
		file->off = root->delta + fs->base + first->physical;
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
	if (handle->blocked || (!handle->stream && handle->source && handle->source->compressed) || file->type == 'd') {
		return -1;
	}
	if (offset >= file->size) {
		return 0;
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
		HfsRun *run = hfs_run_at (&handle->data->runs, offset + done);
		if (!run) {
			file->flags |= R_FS_FILE_PARTIAL;
			break;
		}
		int chunk = R_MIN ((ut64)(length - done), run->size - (offset + done - run->logical));
		if (!hfs_fork_read (handle->fs, handle->data, offset + done, file->data + done, chunk)) {
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
	bool fork_path = false;
	HfsEntry *directory = NULL;
	if (fs->native && id == UT64_MAX) {
		id = hfs_fork_path (fs, path, &fork_path, &directory);
	}
	RFSFile *native = id != UT64_MAX? FSP(_forensic_open_id) (root, id, 0): NULL;
	HfsFile *handle = native? native->ptr: NULL;
	if (handle && handle->blocked) {
		FSP(_forensic_close) (native);
		r_fs_file_free (native);
		return NULL;
	}
	if (native && (native->type == 'f' || handle->stream)
			&& (handle->stream || !handle->source->compressed)) {
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
	if (fork_path) {
		return NULL;
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

static bool hfs_stream_visible(ut32 flags, int view) {
	return view & (flags & R_FS_FILE_DELETED? R_FS_VIEW_DELETED: R_FS_VIEW_NORMAL | R_FS_VIEW_SPECIAL);
}

static RList *hfs_stream_directory(HfsFS *fs, HfsEntry *entry, int view) {
	if (entry->cycle || (entry->link_kind && !entry->target)) {
		return NULL;
	}
	HfsEntry *source = entry->target? entry->target: entry;
	ut32 flags = entry->flags | source->flags;
	RList *result = r_list_newf ((RListFree)r_fs_file_free);
	if (entry->type != 'd' && hfs_stream_visible (flags, view)) {
		RFSFile *file = r_fs_file_new (fs->root, "data");
		file->id = entry->id;
		file->size = entry->size;
		file->type = 'f';
		file->flags = flags;
		r_list_append (result, file);
	}
	RListIter *iter;
	HfsStream *stream;
	r_list_foreach (source->streams, iter, stream) {
		ut32 stream_flags = flags | stream->flags;
		if (!hfs_stream_visible (stream_flags, view)) {
			continue;
		}
		char *name = stream->resource? strdup ("rsrc"): r_str_newf ("xattr:%s", stream->name);
		if (!name) {
			continue;
		}
		RFSFile *file = r_fs_file_new (fs->root, name);
		free (name);
		file->id = stream->id;
		file->size = stream->data.size;
		file->type = 'f';
		file->flags = stream_flags;
		r_list_append (result, file);
	}
	return result;
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
	if (!carve && !directory && id == UT64_MAX) {
		bool recognized;
		ut64 selected = hfs_fork_path (fs, path, &recognized, &directory);
		if (recognized && directory && selected == UT64_MAX
				&& (r_str_endswith (path, "/..namedfork") || r_str_endswith (path, "/..namedfork/"))) {
			return hfs_stream_directory (fs, directory, view);
		}
		return NULL;
	}
	if (!carve && directory && directory->type != 'd') {
		return hfs_stream_directory (fs, directory, view);
	}
	if (!carve && (!directory || directory->cycle || (directory->link_kind && !directory->target))) {
		return NULL;
	}
	HfsEntry *source = directory && directory->target? directory->target: directory;
	RList *children = carve? fs->entries: ht_up_find (fs->children, source->id, NULL);
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
	if (carve) {
		HfsStream *stream;
		r_list_foreach (fs->streams, iter, stream) {
			if (stream->entry || stream->resource || !(stream->flags & R_FS_FILE_DELETED)) {
				continue;
			}
			char *name = r_str_newf ("cnid-%u:xattr:%s", stream->cnid, stream->name);
			if (!name) {
				continue;
			}
			RFSFile *file = r_fs_file_new (root, name);
			free (name);
			file->id = stream->id;
			file->size = stream->data.size;
			file->type = 'f';
			file->flags = stream->flags;
			r_list_append (result, file);
		}
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
	ht_up_free (fs->directories);
	ht_up_free (fs->thread_index);
	ht_up_free (fs->versions);
	ht_up_free (fs->inodes);
	ht_up_free (fs->stream_ids);
	r_list_free (fs->streams);
	r_list_free (fs->threads);
	size_t i;
	for (i = 0; i < RVecHfsAttribute_length (&fs->attrs); i++) {
		HfsAttribute *attribute = RVecHfsAttribute_at (&fs->attrs, i);
		free (attribute->name);
		hfs_fork_fini (&attribute->data);
	}
	RVecHfsAttribute_fini (&fs->attrs);
	r_list_free (fs->entries);
	free (fs);
}
