/* radare - LGPL - Copyright 2022 - condret */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>

typedef struct io_treebuf_t {
	RRBTree *tree;
	ut64 seek;
} IOTreeBuf;

typedef struct io_treebuf_chunk_t {
	RInterval itv;
	ut8 *buf;
} IOTreeBufChunk;

static void _treebuf_chunk_free(void *data) {
	if (!data) {
		return;
	}
	IOTreeBufChunk *chunk = (IOTreeBufChunk *)data;
	free (chunk->buf);
	free (chunk);
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return !strcmp (pathname, "treebuf://");
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
	if (cmd && !strcmp (cmd, "reset")) {
		RRBTree *tree = r_crbtree_new (_treebuf_chunk_free);
		if (!tree) {
			free (tree);
			R_LOG_ERROR ("Allocation failed");
			return "-1";
		}
		IOTreeBuf *treebuf = (IOTreeBuf *)desc->data;
		r_crbtree_free (treebuf->tree);
		treebuf->tree = tree;
	}
	return "0";
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, false)) {
		return NULL;
	}
	IOTreeBuf *treebuf = R_NEW0 (IOTreeBuf);
	if (!treebuf) {
		R_LOG_ERROR ("Allocation failed");
		return NULL;
	}
	treebuf->tree = r_crbtree_new (_treebuf_chunk_free);
	if (!treebuf->tree) {
		free (treebuf);
		R_LOG_ERROR ("Allocation failed");
		return NULL;
	}
	RIODesc *desc = r_io_desc_new (io, &r_io_plugin_treebuf, pathname, R_PERM_RW, mode, treebuf);
	if (!desc) {
		r_crbtree_free (treebuf->tree);
		free (treebuf);
		R_LOG_ERROR ("Allocation failed");
	}
	return desc;
}

static bool __close(RIODesc *desc) {
	r_crbtree_free (((IOTreeBuf *)desc->data)->tree);
	R_FREE (desc->data);
	return true;
}

static ut64 __lseek(RIO* io, RIODesc *desc, ut64 offset, int whence) {
	IOTreeBuf *treebuf = (IOTreeBuf *)desc->data;
	switch (whence) {
	case R_IO_SEEK_SET:
		return treebuf->seek = offset;
	case R_IO_SEEK_END:
		return treebuf->seek = UT64_MAX;
	case R_IO_SEEK_CUR:
		return treebuf->seek = R_MAX (treebuf->seek, treebuf->seek + offset);
	}
	R_LOG_ERROR ("Invalid whence %d", whence);
	return treebuf->seek;
}

static int _treebuf_chunk_find (void *incoming, void *in, void *user) {
	RInterval *itv = (RInterval *)incoming;
	IOTreeBufChunk *chunk = (IOTreeBufChunk *)in;
	if (r_itv_overlap (itv[0], chunk->itv)) {
		return 0;
	}
	if (r_itv_begin (itv[0]) < r_itv_begin (chunk->itv)) {
		return -1;
	}
	return 1;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
	IOTreeBuf *treebuf = (IOTreeBuf *)desc->data;
	RInterval search_itv = {treebuf->seek, R_MIN ((ut64)len, UT64_MAX - treebuf->seek)};
	memset (buf, io->Oxff, len);
	RRBNode *node = r_crbtree_find_node (treebuf->tree, &search_itv, _treebuf_chunk_find, NULL);
	if (!node) {
		treebuf->seek = r_itv_end (search_itv);
		return (int)r_itv_size (search_itv);
	}
	IOTreeBufChunk *chunk = NULL;
	RRBNode *prev = r_rbnode_prev (node);
	while (prev) {
		chunk = (IOTreeBufChunk *)prev->data;
		if (!r_itv_overlap (chunk->itv, search_itv)) {
			break;
		}
		node = prev;
		prev = r_rbnode_prev (prev);
	}
	chunk = (IOTreeBufChunk *)node->data;
	do {
		ut64 addr = R_MAX (r_itv_begin (search_itv), r_itv_begin (chunk->itv));
		ut8 *dst = &buf[addr - r_itv_begin (search_itv)];
		ut8 *src = &chunk->buf[addr - r_itv_begin (chunk->itv)];
		memcpy (dst, src, (size_t)(R_MIN (r_itv_end (search_itv), r_itv_end (chunk->itv)) - addr));
		node = r_rbnode_next (node);
		chunk = node? (IOTreeBufChunk *)node->data: NULL;
	} while (chunk && r_itv_overlap (chunk->itv, search_itv));
	treebuf->seek = r_itv_end (search_itv);
	return (int)r_itv_size (search_itv);
}

static int _treebuf_chunk_insert (void *incoming, void *in, void *user) {
	IOTreeBufChunk *incoming_chunk = (IOTreeBufChunk *)incoming;
	IOTreeBufChunk *in_chunk = (IOTreeBufChunk *)in;
	if (r_itv_begin (incoming_chunk->itv) < r_itv_begin (in_chunk->itv)) {
		return -1;
	}
	if (r_itv_begin (incoming_chunk->itv) > r_itv_begin (in_chunk->itv)) {
		return 1;
	}
	return 0;
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int len) {
	IOTreeBuf *treebuf = (IOTreeBuf *)desc->data;
	RInterval search_itv = {treebuf->seek, R_MIN ((ut64)len, UT64_MAX - treebuf->seek)};
	RRBNode *node = r_crbtree_find_node (treebuf->tree, &search_itv, _treebuf_chunk_find, NULL);
	if (!node) {
		IOTreeBufChunk *chunk = R_NEW0 (IOTreeBufChunk);
		if (!chunk) {
			return -1;
		}
		chunk->buf = R_NEWS (ut8, r_itv_size (search_itv));
		chunk->itv = search_itv;
		if (!chunk->buf || !r_crbtree_insert (treebuf->tree, chunk, _treebuf_chunk_insert, NULL)) {
			free (chunk->buf);
			free (chunk);
			return -1;
		}
		memcpy (chunk->buf, buf, r_itv_size (search_itv));
		treebuf->seek = r_itv_end (search_itv);
		return (int)r_itv_size (search_itv);
	}
	IOTreeBufChunk *chunk = NULL;
	RRBNode *prev = r_rbnode_prev (node);
	while (prev) {
		chunk = (IOTreeBufChunk *)prev->data;
		if (!r_itv_overlap (chunk->itv, search_itv)) {
			break;
		}
		node = prev;
		prev = r_rbnode_prev (prev);
	}
	chunk = (IOTreeBufChunk *)node->data;
	if (r_itv_include (chunk->itv, search_itv)) {
		ut8 *dst = &chunk->buf[r_itv_begin (search_itv) - r_itv_begin (chunk->itv)];
		memcpy (dst, buf, r_itv_size (search_itv));
		treebuf->seek = r_itv_end (search_itv);
		return (int)r_itv_size (search_itv);
	}
	if (r_itv_begin (chunk->itv) < r_itv_begin (search_itv)) {
		chunk->itv.size = r_itv_begin (search_itv) - r_itv_begin (chunk->itv);
		chunk->buf = realloc (chunk->buf, r_itv_size (chunk->itv));
	}
	node = r_rbnode_next (node);
	if (node) {
		chunk = node? (IOTreeBufChunk *)node->data: NULL;
		while (chunk && r_itv_include (search_itv, chunk->itv)) {
			node = r_rbnode_next (node);
			r_crbtree_delete (treebuf->tree, &chunk->itv, _treebuf_chunk_find, NULL);
			chunk = node? (IOTreeBufChunk *)node->data: NULL;
		}
	}
	if (chunk && r_itv_end (search_itv) >= r_itv_begin (chunk->itv)) {
		chunk->buf = realloc (chunk->buf, r_itv_end (chunk->itv) - r_itv_begin (search_itv));
		memmove (&chunk->buf[r_itv_size (search_itv)],
			&chunk->buf[r_itv_end (search_itv) - r_itv_begin (chunk->itv)],
			r_itv_end (chunk->itv) - r_itv_end (search_itv));
		memcpy (chunk->buf, buf, r_itv_size (search_itv));
		chunk->itv.size = r_itv_end (chunk->itv) - r_itv_begin (search_itv);
		chunk->itv.addr = search_itv.addr;
		treebuf->seek = r_itv_end (search_itv);
		return (int)r_itv_size (search_itv);
	}
	chunk = R_NEW0 (IOTreeBufChunk);
	chunk->buf = R_NEWS (ut8, r_itv_size (search_itv));
	chunk->itv = search_itv;
	memcpy (chunk->buf, buf, r_itv_size (search_itv));
	r_crbtree_insert (treebuf->tree, chunk, _treebuf_chunk_insert, NULL);
	treebuf->seek = r_itv_end (search_itv);
	return (int)r_itv_size (search_itv);
}

RIOPlugin r_io_plugin_treebuf = {
	.name = "treebuf",
	.desc = "Dynamic sparse like buffer without size restriction",
	.uris = "treebuf://",
	.license = "LGPL",
	.system = __system,
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek,
	.write = __write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_treebuf,
	.version = R2_VERSION
};
#endif
