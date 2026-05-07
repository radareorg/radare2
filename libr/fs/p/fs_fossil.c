/* radare2 - MIT - Copyright 2026 - pancake */

#define R_LOG_ORIGIN "fs.fossil"

#include <r_fs.h>
#include <r_lib.h>
#include <r_util.h>

#define FOSSIL_HEADER_MAGIC 0x3776ae89
#define FOSSIL_HEADER_VERSION 1
#define FOSSIL_HEADER_OFFSET (128 * 1024)
#define FOSSIL_HEADER_SIZE 512
#define FOSSIL_MAX_BLOCK_SIZE (64 * 1024)
#define FOSSIL_SUPER_MAGIC 0x2340a3b1
#define FOSSIL_SUPER_VERSION 1
#define FOSSIL_SUPER_SIZE 512
#define FOSSIL_LABEL_SIZE 14
#define FOSSIL_VT_SCORE_SIZE 20
#define FOSSIL_VT_ENTRY_SIZE 40
#define FOSSIL_META_MAGIC 0x5656fc7a
#define FOSSIL_META_HEADER_SIZE 12
#define FOSSIL_META_INDEX_SIZE 4
#define FOSSIL_DIR_MAGIC 0x1c4d9072
#define FOSSIL_ROOT_TAG 1
#define FOSSIL_NIL_BLOCK UT32_MAX

#define FOSSIL_ENTRY_ACTIVE 0x01
#define FOSSIL_ENTRY_DIR 0x02
#define FOSSIL_ENTRY_DEPTH_MASK 0x1c
#define FOSSIL_ENTRY_DEPTH_SHIFT 2
#define FOSSIL_ENTRY_LOCAL 0x20

#define FOSSIL_MODE_LINK (1 << 14)
#define FOSSIL_MODE_DIR (1 << 15)

enum {
	FOSSIL_BS_FREE = 0,
	FOSSIL_BS_BAD = 0xff,
	FOSSIL_BS_ALLOC = 1 << 0,
	FOSSIL_BS_COPIED = 1 << 1,
	FOSSIL_BS_VENTI = 1 << 2,
	FOSSIL_BS_CLOSED = 1 << 3,
	FOSSIL_BS_MASK = FOSSIL_BS_ALLOC | FOSSIL_BS_COPIED | FOSSIL_BS_VENTI | FOSSIL_BS_CLOSED,
};

enum {
	FOSSIL_BT_DATA = 0,
	FOSSIL_BT_DIR = 1 << 3,
	FOSSIL_BT_LEVEL_MASK = 7,
	FOSSIL_BT_MAX = 1 << 4,
};

typedef struct {
	RIOBind *iob;
	ut64 delta;
	ut16 block_size;
	ut32 super;
	ut32 label;
	ut32 data;
	ut32 end;
	ut32 epoch_low;
	ut32 epoch_high;
	ut64 qid;
	ut32 active;
	char name[129];
} FossilFS;

typedef struct {
	ut8 state;
	ut8 type;
	ut32 epoch;
	ut32 epoch_close;
	ut32 tag;
} FossilLabel;

typedef struct {
	ut32 gen;
	ut16 psize;
	ut16 dsize;
	ut8 depth;
	ut8 flags;
	ut64 size;
	ut8 score[FOSSIL_VT_SCORE_SIZE];
	ut32 tag;
	ut32 snap;
	ut8 archive;
} FossilEntry;

typedef struct {
	char *elem;
	char *uid;
	char *gid;
	char *mid;
	ut32 entry;
	ut32 gen;
	ut32 mentry;
	ut32 mgen;
	ut64 size;
	ut64 qid;
	ut32 mtime;
	ut32 mcount;
	ut32 ctime;
	ut32 atime;
	ut32 mode;
} FossilDirEntry;

typedef struct {
	int size;
	int maxindex;
	int nindex;
	ut8 *buf;
} FossilMetaBlock;

typedef struct {
	FossilEntry source;
	FossilEntry msource;
	FossilDirEntry dir;
} FossilNode;

typedef struct {
	FossilEntry source;
} FossilOpenFile;

static inline bool fossil_read_at(FossilFS *fs, ut64 offset, ut8 *buf, int len) {
	return fs->iob->read_at (fs->iob->io, fs->delta + offset, buf, len);
}

static inline ut64 fossil_part_off(FossilFS *fs, ut32 part, ut32 addr) {
	return ((ut64)part + addr) * fs->block_size;
}

static bool fossil_is_zero_score(const ut8 *score) {
	int i;
	for (i = 0; i < FOSSIL_VT_SCORE_SIZE; i++) {
		if (score[i]) {
			return false;
		}
	}
	return true;
}

static ut32 fossil_score_to_local(const ut8 *score) {
	int i;
	for (i = 0; i < FOSSIL_VT_SCORE_SIZE - 4; i++) {
		if (score[i]) {
			return FOSSIL_NIL_BLOCK;
		}
	}
	return r_read_be32 (score + FOSSIL_VT_SCORE_SIZE - 4);
}

static bool fossil_label_unpack(FossilLabel *l, const ut8 *p) {
	l->state = p[0];
	l->type = p[1];
	l->epoch = r_read_be32 (p + 2);
	l->epoch_close = r_read_be32 (p + 6);
	l->tag = r_read_be32 (p + 10);
	if (l->type > FOSSIL_BT_MAX) {
		return false;
	}
	if (l->state != FOSSIL_BS_FREE && l->state != FOSSIL_BS_BAD) {
		if (!(l->state & FOSSIL_BS_ALLOC) || (l->state & ~FOSSIL_BS_MASK)) {
			return false;
		}
		if ((l->state & FOSSIL_BS_CLOSED) != 0) {
			return l->epoch_close != UT32_MAX;
		}
		return l->epoch_close == UT32_MAX;
	}
	return true;
}

static bool fossil_read_label(FossilFS *fs, ut32 addr, FossilLabel *label) {
	int lpb = fs->block_size / FOSSIL_LABEL_SIZE;
	if (lpb < 1) {
		return false;
	}
	ut8 *buf = malloc (fs->block_size);
	if (!buf) {
		return false;
	}
	if (!fossil_read_at (fs, fossil_part_off (fs, fs->label, addr / lpb), buf, fs->block_size)) {
		free (buf);
		return false;
	}
	bool ok = fossil_label_unpack (label, buf + (addr % lpb) * FOSSIL_LABEL_SIZE);
	free (buf);
	return ok;
}

static bool fossil_read_local_block(FossilFS *fs, ut32 addr, int type, ut32 tag, ut8 *buf) {
	if (addr >= fs->end - fs->data) {
		R_LOG_ERROR ("bad local block address 0x%08"PFMT32x, addr);
		return false;
	}
	FossilLabel label;
	if (!fossil_read_label (fs, addr, &label)) {
		R_LOG_ERROR ("bad label for block 0x%08"PFMT32x, addr);
		return false;
	}
	if (label.type != type || label.tag != tag) {
		R_LOG_ERROR ("label mismatch at block 0x%08"PFMT32x" type=%d/%d tag=0x%08"PFMT32x"/0x%08"PFMT32x,
			addr, label.type, type, label.tag, tag);
		return false;
	}
	return fossil_read_at (fs, fossil_part_off (fs, fs->data, addr), buf, fs->block_size);
}

static bool fossil_load_score(FossilFS *fs, const ut8 *score, int type, ut32 tag, ut8 *buf) {
	ut32 addr = fossil_score_to_local (score);
	if (addr != FOSSIL_NIL_BLOCK && tag) {
		return fossil_read_local_block (fs, addr, type, tag, buf);
	}
	if (fossil_is_zero_score (score)) {
		memset (buf, 0, fs->block_size);
		return true;
	}
	if (addr == FOSSIL_NIL_BLOCK) {
		R_LOG_ERROR ("Venti-backed Fossil blocks are not supported");
		return false;
	}
	return fossil_read_local_block (fs, addr, type, tag, buf);
}

static bool fossil_entry_unpack(FossilEntry *e, const ut8 *p, int index) {
	p += index * FOSSIL_VT_ENTRY_SIZE;
	e->gen = r_read_be32 (p);
	e->psize = r_read_be16 (p + 4);
	e->dsize = r_read_be16 (p + 6);
	e->flags = p[8];
	e->depth = (e->flags & FOSSIL_ENTRY_DEPTH_MASK) >> FOSSIL_ENTRY_DEPTH_SHIFT;
	e->flags &= ~FOSSIL_ENTRY_DEPTH_MASK;
	e->size = ((ut64)r_read_be16 (p + 14) << 32) | r_read_be32 (p + 16);
	if (e->flags & FOSSIL_ENTRY_LOCAL) {
		e->archive = p[27];
		e->snap = r_read_be32 (p + 28);
		e->tag = r_read_be32 (p + 32);
		memset (e->score, 0, 16);
		memcpy (e->score + 16, p + 36, 4);
	} else {
		e->archive = 0;
		e->snap = 0;
		e->tag = 0;
		memcpy (e->score, p + 20, FOSSIL_VT_SCORE_SIZE);
	}
	return true;
}

static bool fossil_entry_is_valid(FossilFS *fs, FossilEntry *e) {
	if (!(e->flags & FOSSIL_ENTRY_ACTIVE) || e->psize < 256 || e->dsize < 256) {
		return false;
	}
	return e->psize <= fs->block_size && e->dsize <= fs->block_size;
}

static bool fossil_read_source_block(FossilFS *fs, FossilEntry *e, ut32 bn, ut8 *out) {
	if (e->depth > FOSSIL_BT_LEVEL_MASK || e->psize < FOSSIL_VT_SCORE_SIZE) {
		return false;
	}
	int base_type = (e->flags & FOSSIL_ENTRY_DIR)? FOSSIL_BT_DIR: FOSSIL_BT_DATA;
	if (!e->depth) {
		return fossil_load_score (fs, e->score, base_type, e->tag, out);
	}
	int ppb = e->psize / FOSSIL_VT_SCORE_SIZE;
	if (ppb < 1) {
		return false;
	}
	int index[FOSSIL_BT_LEVEL_MASK] = { 0 };
	ut32 n = bn;
	int i;
	for (i = 0; n > 0 && i < e->depth; i++) {
		index[i] = n % ppb;
		n /= ppb;
	}
	if (n) {
		return false;
	}
	ut8 score[FOSSIL_VT_SCORE_SIZE];
	memcpy (score, e->score, sizeof (score));
	ut8 *buf = malloc (fs->block_size);
	if (!buf) {
		return false;
	}
	for (i = e->depth; i > 0; i--) {
		if (!fossil_load_score (fs, score, base_type | i, e->tag, buf)) {
			free (buf);
			return false;
		}
		if (index[i - 1] * FOSSIL_VT_SCORE_SIZE + FOSSIL_VT_SCORE_SIZE > e->psize) {
			free (buf);
			return false;
		}
		memcpy (score, buf + index[i - 1] * FOSSIL_VT_SCORE_SIZE, FOSSIL_VT_SCORE_SIZE);
	}
	bool ok = fossil_load_score (fs, score, base_type, e->tag, out);
	free (buf);
	return ok;
}

static int fossil_source_read(FossilFS *fs, FossilEntry *e, ut64 off, ut8 *out, int len) {
	if (off >= e->size) {
		return 0;
	}
	if ((ut64)len > e->size - off) {
		len = (int)(e->size - off);
	}
	ut8 *buf = malloc (fs->block_size);
	if (!buf) {
		return -1;
	}
	int done = 0;
	while (done < len) {
		ut32 bn = off / e->dsize;
		int boff = off % e->dsize;
		int n = R_MIN (len - done, e->dsize - boff);
		if (!fossil_read_source_block (fs, e, bn, buf)) {
			free (buf);
			return -1;
		}
		memcpy (out + done, buf + boff, n);
		done += n;
		off += n;
	}
	free (buf);
	return done;
}

static bool fossil_source_open(FossilFS *fs, FossilEntry *parent, ut32 offset, FossilEntry *child) {
	int epb = parent->dsize / FOSSIL_VT_ENTRY_SIZE;
	if (epb < 1) {
		return false;
	}
	ut8 *buf = malloc (fs->block_size);
	if (!buf) {
		return false;
	}
	bool ok = fossil_read_source_block (fs, parent, offset / epb, buf)
		&& fossil_entry_unpack (child, buf, offset % epb)
		&& fossil_entry_is_valid (fs, child);
	free (buf);
	return ok;
}

static bool fossil_meta_unpack(FossilMetaBlock *mb, ut8 *buf, int n) {
	ut32 magic = r_read_be32 (buf);
	if (magic != FOSSIL_META_MAGIC && magic != FOSSIL_META_MAGIC - 1) {
		return false;
	}
	mb->size = r_read_be16 (buf + 4);
	mb->maxindex = r_read_be16 (buf + 8);
	mb->nindex = r_read_be16 (buf + 10);
	mb->buf = buf;
	int min = FOSSIL_META_HEADER_SIZE + mb->maxindex * FOSSIL_META_INDEX_SIZE;
	if (mb->nindex > mb->maxindex || mb->size > n || min > n) {
		return false;
	}
	int i;
	for (i = 0; i < mb->nindex; i++) {
		ut8 *p = buf + FOSSIL_META_HEADER_SIZE + i * FOSSIL_META_INDEX_SIZE;
		ut16 off = r_read_be16 (p);
		ut16 size = r_read_be16 (p + 2);
		if (off < min || off + size > mb->size || size < 8) {
			return false;
		}
		if (r_read_be32 (buf + off) != FOSSIL_DIR_MAGIC) {
			return false;
		}
	}
	return true;
}

static void fossil_de_fini(FossilDirEntry *de) {
	free (de->elem);
	free (de->uid);
	free (de->gid);
	free (de->mid);
	memset (de, 0, sizeof (*de));
}

static bool fossil_str_unpack(char **s, const ut8 **p, int *n) {
	if (*n < 2) {
		return false;
	}
	ut16 len = r_read_be16 (*p);
	*p += 2;
	*n -= 2;
	if (len > *n) {
		return false;
	}
	*s = r_str_ndup ((const char *)*p, len);
	if (!*s) {
		return false;
	}
	*p += len;
	*n -= len;
	return true;
}

static bool fossil_de_unpack(FossilDirEntry *de, const ut8 *p, int n) {
	memset (de, 0, sizeof (*de));
	if (n < 6 || r_read_be32 (p) != FOSSIL_DIR_MAGIC) {
		return false;
	}
	p += 4;
	n -= 4;
	ut16 version = r_read_be16 (p);
	p += 2;
	n -= 2;
	if (version < 7 || version > 9 || !fossil_str_unpack (&de->elem, &p, &n) || n < 4) {
		goto err;
	}
	de->entry = r_read_be32 (p);
	p += 4;
	n -= 4;
	if (version < 9) {
		de->mentry = de->entry + 1;
	} else {
		if (n < 12) {
			goto err;
		}
		de->gen = r_read_be32 (p);
		de->mentry = r_read_be32 (p + 4);
		de->mgen = r_read_be32 (p + 8);
		p += 12;
		n -= 12;
	}
	if (n < 8) {
		goto err;
	}
	de->qid = r_read_be64 (p);
	p += 8;
	n -= 8;
	if (version == 7) {
		if (n < FOSSIL_VT_SCORE_SIZE) {
			goto err;
		}
		p += FOSSIL_VT_SCORE_SIZE;
		n -= FOSSIL_VT_SCORE_SIZE;
	}
	if (!fossil_str_unpack (&de->uid, &p, &n)
		|| !fossil_str_unpack (&de->gid, &p, &n)
		|| !fossil_str_unpack (&de->mid, &p, &n)
		|| n < 20) {
		goto err;
	}
	de->mtime = r_read_be32 (p);
	de->mcount = r_read_be32 (p + 4);
	de->ctime = r_read_be32 (p + 8);
	de->atime = r_read_be32 (p + 12);
	de->mode = r_read_be32 (p + 16);
	p += 20;
	n -= 20;
	while (n > 0) {
		if (n < 3) {
			goto err;
		}
		ut16 len = r_read_be16 (p + 1);
		p += 3;
		n -= 3;
		if (len > n) {
			goto err;
		}
		p += len;
		n -= len;
	}
	return true;
err:
	fossil_de_fini (de);
	return false;
}

static bool fossil_meta_entry(FossilMetaBlock *mb, int index, FossilDirEntry *de) {
	if (index < 0 || index >= mb->nindex) {
		return false;
	}
	ut8 *p = mb->buf + FOSSIL_META_HEADER_SIZE + index * FOSSIL_META_INDEX_SIZE;
	ut16 off = r_read_be16 (p);
	ut16 size = r_read_be16 (p + 2);
	return fossil_de_unpack (de, mb->buf + off, size);
}

static void fossil_node_fini(FossilNode *node) {
	fossil_de_fini (&node->dir);
}

static bool fossil_root_source(FossilFS *fs, FossilEntry *root) {
	ut8 *buf = malloc (fs->block_size);
	if (!buf) {
		return false;
	}
	bool ok = fossil_read_local_block (fs, fs->active, FOSSIL_BT_DIR, FOSSIL_ROOT_TAG, buf)
		&& fossil_entry_unpack (root, buf, 0)
		&& fossil_entry_is_valid (fs, root);
	free (buf);
	return ok;
}

static bool fossil_root_node(FossilFS *fs, FossilNode *node) {
	memset (node, 0, sizeof (*node));
	FossilEntry root;
	if (!fossil_root_source (fs, &root)) {
		R_LOG_ERROR ("cannot read Fossil active root");
		return false;
	}
	if (!fossil_source_open (fs, &root, 0, &node->source)
		|| !fossil_source_open (fs, &root, 1, &node->msource)) {
		R_LOG_ERROR ("cannot open Fossil root sources");
		return false;
	}
	FossilEntry rootmeta;
	if (!fossil_source_open (fs, &root, 2, &rootmeta)) {
		R_LOG_ERROR ("cannot open Fossil root metadata source");
		return false;
	}
	ut8 *buf = malloc (fs->block_size);
	if (!buf) {
		return false;
	}
	FossilMetaBlock mb;
	bool ok = fossil_read_source_block (fs, &rootmeta, 0, buf);
	if (ok) {
		ok = fossil_meta_unpack (&mb, buf, rootmeta.dsize);
		if (!ok) {
			R_LOG_ERROR ("cannot unpack Fossil root metadata block");
		}
	}
	if (ok) {
		ok = fossil_meta_entry (&mb, 0, &node->dir);
		if (!ok) {
			R_LOG_ERROR ("cannot unpack Fossil root directory entry");
		}
	}
	free (buf);
	if (ok) {
		node->dir.mode |= FOSSIL_MODE_DIR;
	}
	return ok;
}

static bool fossil_dir_lookup(FossilFS *fs, FossilNode *dir, const char *name, FossilNode *child) {
	memset (child, 0, sizeof (*child));
	ut32 nb = (dir->msource.size + dir->msource.dsize - 1) / dir->msource.dsize;
	ut8 *buf = malloc (fs->block_size);
	if (!buf) {
		return false;
	}
	ut32 bo;
	for (bo = 0; bo < nb; bo++) {
		FossilMetaBlock mb;
		if (!fossil_read_source_block (fs, &dir->msource, bo, buf) || !fossil_meta_unpack (&mb, buf, dir->msource.dsize)) {
			break;
		}
		int i;
		for (i = 0; i < mb.nindex; i++) {
			FossilDirEntry de;
			if (!fossil_meta_entry (&mb, i, &de)) {
				continue;
			}
			if (!strcmp (de.elem, name)) {
				child->dir = de;
				bool ok = fossil_source_open (fs, &dir->source, de.entry, &child->source)
					&& child->source.gen == de.gen;
				if (ok && (de.mode & FOSSIL_MODE_DIR)) {
					ok = fossil_source_open (fs, &dir->source, de.mentry, &child->msource)
						&& child->msource.gen == de.mgen;
				}
				free (buf);
				if (!ok) {
					fossil_node_fini (child);
				}
				return ok;
			}
			fossil_de_fini (&de);
		}
	}
	free (buf);
	return false;
}

static bool fossil_resolve(FossilFS *fs, const char *path, FossilNode *node) {
	if (!fossil_root_node (fs, node)) {
		return false;
	}
	if (R_STR_ISEMPTY (path) || !strcmp (path, "/")) {
		return true;
	}
	char *path_copy = strdup (path);
	if (!path_copy) {
		fossil_node_fini (node);
		return false;
	}
	RList *parts = r_str_split_list (path_copy, "/", 0);
	if (!parts) {
		free (path_copy);
		fossil_node_fini (node);
		return false;
	}
	RListIter *iter;
	const char *part;
	r_list_foreach (parts, iter, part) {
		if (R_STR_ISEMPTY (part)) {
			continue;
		}
		FossilNode child;
		if (!(node->dir.mode & FOSSIL_MODE_DIR) || !fossil_dir_lookup (fs, node, part, &child)) {
			r_list_free (parts);
			free (path_copy);
			fossil_node_fini (node);
			return false;
		}
		fossil_node_fini (node);
		*node = child;
	}
	r_list_free (parts);
	free (path_copy);
	return true;
}

static RFSFile *fossil_file_from_node(RFSRoot *root, const char *path, FossilNode *node) {
	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}
	if (node->dir.mode & FOSSIL_MODE_DIR) {
		file->type = R_FS_FILE_TYPE_DIRECTORY;
	} else if (node->dir.mode & FOSSIL_MODE_LINK) {
		file->type = R_FS_FILE_TYPE_SPECIAL;
	} else {
		file->type = R_FS_FILE_TYPE_REGULAR;
		file->size = node->source.size > UT32_MAX? UT32_MAX: (ut32)node->source.size;
	}
	file->time = node->dir.mtime;
	file->perm = node->dir.mode & 0777;
	return file;
}

static bool fs_fossil_mount(RFSRoot *root) {
	R_RETURN_VAL_IF_FAIL (root, false);
	FossilFS *fs = R_NEW0 (FossilFS);
	fs->iob = &root->iob;
	fs->delta = root->delta;
	ut64 io_size = 0;
	if (fs->iob->io && fs->iob->io->desc && fs->iob->desc_size) {
		io_size = fs->iob->desc_size (fs->iob->io->desc);
	}
	if (io_size <= fs->delta || io_size - fs->delta < FOSSIL_HEADER_OFFSET + FOSSIL_HEADER_SIZE) {
		goto fail;
	}
	ut64 part_size = io_size - fs->delta;
	ut8 buf[FOSSIL_HEADER_SIZE];
	if (!fossil_read_at (fs, FOSSIL_HEADER_OFFSET, buf, sizeof (buf))) {
		goto fail;
	}
	if (r_read_be32 (buf) != FOSSIL_HEADER_MAGIC || r_read_be16 (buf + 4) != FOSSIL_HEADER_VERSION) {
		goto fail;
	}
	fs->block_size = r_read_be16 (buf + 6);
	fs->super = r_read_be32 (buf + 8);
	fs->label = r_read_be32 (buf + 12);
	fs->data = r_read_be32 (buf + 16);
	fs->end = r_read_be32 (buf + 20);
	if (fs->block_size < 512
		|| (ut64)fs->block_size > FOSSIL_MAX_BLOCK_SIZE
		|| (fs->block_size & (fs->block_size - 1))
		|| fs->super >= fs->label || fs->label >= fs->data || fs->data >= fs->end) {
		goto fail;
	}
	ut64 end_size = 0;
	int lpb = fs->block_size / FOSSIL_LABEL_SIZE;
	ut64 label_blocks = ((ut64)(fs->end - fs->data) + lpb - 1) / lpb;
	if (label_blocks > fs->data - fs->label
		|| r_mul_overflow ((ut64)fs->end, (ut64)fs->block_size, &end_size)
		|| end_size < FOSSIL_HEADER_OFFSET + FOSSIL_HEADER_SIZE
		|| end_size > part_size) {
		goto fail;
	}
	ut8 sbuf[FOSSIL_SUPER_SIZE];
	if (!fossil_read_at (fs, fossil_part_off (fs, fs->super, 0), sbuf, sizeof (sbuf))
		|| r_read_be32 (sbuf) != FOSSIL_SUPER_MAGIC
		|| r_read_be16 (sbuf + 4) != FOSSIL_SUPER_VERSION) {
		goto fail;
	}
	fs->epoch_low = r_read_be32 (sbuf + 6);
	fs->epoch_high = r_read_be32 (sbuf + 10);
	fs->qid = r_read_be64 (sbuf + 14);
	fs->active = r_read_be32 (sbuf + 22);
	memcpy (fs->name, sbuf + 54, 128);
	fs->name[128] = 0;
	if (!fs->epoch_low || fs->epoch_low > fs->epoch_high || !fs->qid) {
		goto fail;
	}
	root->ptr = fs;
	return true;
fail:
	R_LOG_ERROR ("invalid Fossil filesystem");
	free (fs);
	return false;
}

static void fs_fossil_umount(RFSRoot *root) {
	R_RETURN_IF_FAIL (root);
	free (root->ptr);
	root->ptr = NULL;
}

static RList *fs_fossil_dir(RFSRoot *root, const char *path, R_UNUSED int view) {
	R_RETURN_VAL_IF_FAIL (root, NULL);
	FossilFS *fs = root->ptr;
	FossilNode node;
	if (!fossil_resolve (fs, path, &node)) {
		return NULL;
	}
	if (!(node.dir.mode & FOSSIL_MODE_DIR)) {
		fossil_node_fini (&node);
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	if (!list) {
		fossil_node_fini (&node);
		return NULL;
	}
	ut32 nb = (node.msource.size + node.msource.dsize - 1) / node.msource.dsize;
	ut8 *buf = malloc (fs->block_size);
	if (!buf) {
		fossil_node_fini (&node);
		return list;
	}
	ut32 bo;
	for (bo = 0; bo < nb; bo++) {
		FossilMetaBlock mb;
		if (!fossil_read_source_block (fs, &node.msource, bo, buf) || !fossil_meta_unpack (&mb, buf, node.msource.dsize)) {
			break;
		}
		int i;
		for (i = 0; i < mb.nindex; i++) {
			FossilDirEntry de;
			if (!fossil_meta_entry (&mb, i, &de)) {
				continue;
			}
			RFSFile *file = r_fs_file_new (NULL, de.elem);
			if (file) {
				file->type = (de.mode & FOSSIL_MODE_DIR)? R_FS_FILE_TYPE_DIRECTORY: R_FS_FILE_TYPE_REGULAR;
				file->time = de.mtime;
				file->perm = de.mode & 0777;
				if (!(de.mode & FOSSIL_MODE_DIR)) {
					FossilEntry source;
					if (fossil_source_open (fs, &node.source, de.entry, &source) && source.gen == de.gen) {
						file->size = source.size > UT32_MAX? UT32_MAX: (ut32)source.size;
					}
				}
				r_list_append (list, file);
			}
			fossil_de_fini (&de);
		}
	}
	free (buf);
	fossil_node_fini (&node);
	return list;
}

static RFSFile *fs_fossil_open(RFSRoot *root, const char *path, bool create) {
	R_RETURN_VAL_IF_FAIL (root && path, NULL);
	if (create) {
		return NULL;
	}
	FossilNode node;
	if (!fossil_resolve ((FossilFS *)root->ptr, path, &node)) {
		return NULL;
	}
	RFSFile *file = fossil_file_from_node (root, path, &node);
	if (file && file->type == R_FS_FILE_TYPE_REGULAR) {
		FossilOpenFile *of = R_NEW0 (FossilOpenFile);
		of->source = node.source;
		file->ptr = of;
	}
	fossil_node_fini (&node);
	return file;
}

static int fs_fossil_read(RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (file && file->root && file->ptr, -1);
	FossilFS *fs = file->root->ptr;
	FossilOpenFile *of = file->ptr;
	if (addr >= of->source.size) {
		return 0;
	}
	if ((ut64)len > of->source.size - addr) {
		len = (int)(of->source.size - addr);
	}
	ut8 *data = realloc (file->data, len + 1);
	if (!data) {
		return -1;
	}
	file->data = data;
	int r = fossil_source_read (fs, &of->source, addr, file->data, len);
	if (r >= 0) {
		file->data[r] = 0;
	}
	return r;
}

static void fs_fossil_close(RFSFile *file) {
	if (file) {
		R_FREE (file->ptr);
	}
}

static void fs_fossil_details(RFSRoot *root, RStrBuf *sb) {
	R_RETURN_IF_FAIL (root && root->ptr && sb);
	FossilFS *fs = root->ptr;
	r_strbuf_appendf (sb, "name: %s\n", fs->name);
	r_strbuf_appendf (sb, "block_size: %u\n", fs->block_size);
	r_strbuf_appendf (sb, "epoch_low: %"PFMT32u"\n", fs->epoch_low);
	r_strbuf_appendf (sb, "epoch_high: %"PFMT32u"\n", fs->epoch_high);
	r_strbuf_appendf (sb, "active: 0x%08"PFMT32x"\n", fs->active);
}

RFSPlugin r_fs_plugin_fossil = {
	.meta = {
		.name = "fossil",
		.desc = "Plan 9 Fossil filesystem",
		.license = "MIT",
	},
	.mount = fs_fossil_mount,
	.umount = fs_fossil_umount,
	.dir = fs_fossil_dir,
	.open = fs_fossil_open,
	.read = fs_fossil_read,
	.close = fs_fossil_close,
	.details = fs_fossil_details,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_fossil,
	.version = R2_VERSION
};
#endif
