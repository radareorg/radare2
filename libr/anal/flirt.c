/* radare - LGPL - Copyright 2014 - pancake */

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>


#define IDASIG__FEATURE__STARTUP				0x01
#define IDASIG__FEATURE__CTYPE_CRC				0x02
#define IDASIG__FEATURE__2BYTE_CTYPE			0x04
#define IDASIG__FEATURE__ALT_CTYPE_CRC			0x08
#define IDASIG__FEATURE__COMPRESSED				0x10

typedef struct idasig_t {
	char magic[6];
	ut8  version;
	ut8  arch;
	ut32 file_bs;
	ut16 os_bs;
	ut16 apptype_bs;
	ut16 flags; // specifies sig features
	ut16 modules;
	ut16 crc;
	char ctype[12];
	ut8  name_len;
	ut16 crc_;
} __attribute__((packed)) idasig_t;

typedef struct idasig_v6_t {
	ut32 modules;
} __attribute__((packed)) idasig_v6_t;

typedef struct idasig_v8_t {
	ut32 modules;
	ut16 pattern_size;
} __attribute__((packed)) idasig_v8_t;

typedef struct bb {
	ut8 *buf;
	ut32 pos, size;
} bb;

static bb *init_bb (ut8 *ptr, ut32 size) {
	bb *b = R_NEW0(bb);
	if (!b)
		return NULL;
	b->buf = ptr;
	b->pos = 0;
	b->size = size;
	return b;
}

static ut8 read_byte (bb *b) {
	return b->buf[b->pos++];
}

static ut16 read_short (bb *b) {
	ut16 r =
		b->buf[b->pos+0] << 8 |
		b->buf[b->pos+1];
	b->pos += 2;
	return r;
}

static ut32 read_word (bb *b) {
	ut32 r =
		b->buf[b->pos+0] << 24 |
		b->buf[b->pos+1] << 16 |
		b->buf[b->pos+2] << 8  |
		b->buf[b->pos+3];
	b->pos += 4;
	return r;
}

static ut32 read_shift (bb *b) {
	ut8 r = b->buf[b->pos++];
	if (r&0x80)
		return (r&0x7f) << 8 | b->buf[b->pos++];
	return r;
}

static ut32 r_flirt_explode_mask (bb *b) {
	ut32 r = read_byte(b);

	if ((r&0x80) != 0x80)
		return r;

	if ((r&0xc0) != 0xc0)
		return (r&0x7f) << 8 | read_byte(b);

	if ((r&0xe0) != 0xe0)
		return (r&0x3f) << 24 | read_byte(b) << 16 | read_short(b);

	return read_word(b);
}

#define R_FLIRT_NAME_MAX 1024

typedef struct RFlirtName {
	char name[R_FLIRT_NAME_MAX];
	ut32 offset;
} RFlirtName;

typedef struct RFlirtSubLeaf {
	ut16 check_off;
	ut8  check_val;
	ut8  flags;
	RList *names_list;
} RFlirtSubLeaf;

typedef struct RFlirtLeaf {
	RList *sub_list;
	ut32 crc_len;
	ut32 crc_val;
} RFlirtLeaf;

typedef struct RFlirtNode {
	RList *child_list;
	RList *leaf_list;
	ut32 length;
	ut8 *match;
	ut64 mask;
	ut8 *maskp;
} RFlirtNode;


#define POLY 0x8408
unsigned short crc16(const unsigned char *data_p, size_t length) {
	unsigned char i;
	unsigned int data;

	if ( length == 0 )
		return 0;
	unsigned int crc = 0xFFFF;
	do
	{
		data = *data_p++;
		for ( i=0; i < 8; i++ )
		{
			if ( (crc ^ data) & 1 )
				crc = (crc >> 1) ^ POLY;
			else
				crc >>= 1;
			data >>= 1;
		}
	} while ( --length != 0 );

	crc = ~crc;
	data = crc;
	crc = (crc << 8) | ((data >> 8) & 0xff);
	return (unsigned short)(crc);
}

static int r_flirt_node_match (const ut8 *buf, const ut64 buf_size, const RFlirtNode *node) {
	int i;
	if (node->length > buf_size)
		return R_FALSE;
	for (i = 0; i < node->length; i++) {
		if ((node->match[i]&node->maskp[i]) != (buf[i]&node->maskp[i]))
			return R_FALSE;
	}

	return R_TRUE;
}

static void r_flirt_node_print_pattern (const RFlirtNode *node) {
	int i;
	ut64 cur;
	cur = 1ULL << (node->length - 1);
	for (i = 0; i < node->length; i++) {
		if (node->mask&cur)
			eprintf("..");
		else
			eprintf("%02X", node->match[i]);
		cur >>= 1;
	}
	eprintf("\n");
}

static void r_flirt_subleaf_free (RFlirtSubLeaf *sub) {
	r_list_free(sub->names_list);
}

static void r_flirt_leaf_free (RFlirtLeaf *leaf) {
	leaf->sub_list->free = r_flirt_subleaf_free;
	r_list_free(leaf->sub_list);
}

static void r_flirt_node_free (RFlirtNode *node) {
	free(node->maskp);
	free(node->match);

	if (node->leaf_list) {
		node->leaf_list->free = r_flirt_leaf_free;
		r_list_free(node->leaf_list);
	}

	if (node->child_list) {
		node->child_list->free = r_flirt_node_free;
		r_list_free(node->child_list);
	}
}

void r_flirt_node_print (RFlirtNode *node, const int indent) {
	int i;
	ut64 cur;
	RListIter *it;
	RFlirtLeaf *leaf;

	if (!node)
		return;

	for (i = 0; i < indent; i++) eprintf("\t");
	r_flirt_node_print_pattern(node);

	r_list_foreach(node->leaf_list, it, leaf) {
		RListIter *it;
		RFlirtSubLeaf *sub;
		for (i = 0; i < indent; i++) eprintf("\t");
		eprintf("CRC : %04x (%x)\n", leaf->crc_val, leaf->crc_len);
		r_list_foreach(leaf->sub_list, it, sub) {
			RListIter *it;
			RFlirtName *name;
			eprintf("Flags : %x\n", sub->flags);
			if (sub->flags&1)
				eprintf("check @ %02x = %02x\n", sub->check_off, sub->check_val);
			r_list_foreach(sub->names_list, it, name) {
				for (i = 0; i < indent + 1; i++) eprintf("\t");
				eprintf("> %s @ %x\n", name->name, name->offset);
			}
		}
	}

	RFlirtNode *child;
	r_list_foreach(node->child_list, it, child) {
		r_flirt_node_print(child, indent + 1);
	}
}

static void r_flirt_node_match_buf (const ut64 off, const ut8 *buf, unsigned long buf_size, RFlirtNode *node) {
	RListIter *it1, *it2, *it3, *it4;
	RFlirtNode *c;
	RFlirtLeaf *l;
	RFlirtSubLeaf *s;
	RFlirtName *n;
	ut64 pos;

	int debug = R_FALSE;

	for (pos = off; pos < buf_size; ) {
		if (r_print_is_interrupted ())
			break;

		if (r_flirt_node_match(buf + pos, buf_size - pos, node)) {
			if (pos >= 0x2554 && pos <= 0x2598) {
				/*eprintf("bingo? %x\n", pos);*/
				r_flirt_node_print (node, -1);
				debug = R_TRUE;
			}
			pos += node->length;

			r_list_foreach(node->child_list, it1, c)
				r_flirt_node_match_buf(pos, buf, buf_size, c);

			if (node->leaf_list) {
				r_list_foreach(node->leaf_list, it2, l) {
					if (l->crc_len) {
						const ut16 crc = crc16(buf + pos, l->crc_len);
						eprintf("CRC : %04X CALC : %04X\n", l->crc_val, crc);
						if (crc != l->crc_val)
							continue;
					}

					r_list_foreach(l->sub_list, it3, s) {
						if (debug)
							eprintf("check (%x) %x = %x\n", pos, pos + s->check_off, s->check_val);
						if ((s->flags&1) && buf[pos + s->check_off + 2] != s->check_val) {
							eprintf("discard (%02x != %02x)\n", buf[pos + s->check_off], s->check_val);
							continue;
						}
						eprintf("pass!\n");
						r_list_foreach(s->names_list, it4, n) {
							if (strcmp (n->name, "@__security_check_cookie@4")) {
							eprintf("%x %x - %s\n", pos, n->offset, n->name);
							}
						}
						eprintf("end?\n");
					}
				}
				/*return;*/
			}
		} else
			pos += 1;
	}
}

static void r_flirt_parse_leaf (bb *b, RFlirtNode *node) {
	ut32 flags, off;
	int i;

	node->leaf_list = r_list_new();
	do {
		RFlirtLeaf *leaf = R_NEW0(RFlirtLeaf);
		leaf->sub_list = r_list_new();

		leaf->crc_len = read_byte(b);
		leaf->crc_val = read_short(b);

		r_list_append(node->leaf_list, leaf);
		do {
			RFlirtSubLeaf *sub = R_NEW0(RFlirtSubLeaf);
			sub->names_list = r_list_new();
			r_list_append(leaf->sub_list, sub);

			ut32 length = read_shift(b);

			off = 0;
			do {
				RFlirtName *name = R_NEW0(RFlirtName);
				off += read_shift(b);
				name->offset = off;
				ut8 ch = read_byte(b);
				if (ch < 0x20)
					ch = read_byte(b);
				for (i = 0; ch >= 0x20; i++) {
					if (i > R_FLIRT_NAME_MAX) {
						eprintf("Function name too long\n");
						// TODO:FIXME
						return;
					}
					name->name[i] = (char)ch;
					ch = read_byte(b);
				}
				if (ch == 0x0a) {
					/*name->name[i++] = (char)ch;*/
					ch = read_byte(b);
				}
				name->name[i] = '\0';
				eprintf("name %s (%x)\n", name, ch);
				flags = ch;
				r_list_append(sub->names_list, name);
			} while(flags&0x01);

			if (flags&0x02) {
				sub->flags |= 1;
				eprintf("bbpos %x\n", b->pos);
				sub->check_off = read_shift(b);
				/*sub->check_off = read_short(b)&0xff;*/
				sub->check_val = read_byte(b);
			}

			if (flags&0x04) {
				sub->flags |= 2;
				/*ut32 a = read_shift(b);*/
				ut32 a = read_short(b);
				ut32 p = read_byte(b);
				if (!p)
					p = read_shift(b);
				b->pos += p;
			}
		} while(flags&0x08); // more terminal nodes
	} while(flags&0x10); // more hash entries
}

static void r_flirt_parse_tree (bb *b, RFlirtNode *root_node) {
	int tree_nodes;
	int i, j;
	ut64 bitmap;

	tree_nodes = read_shift(b);

	if (!tree_nodes)
		return r_flirt_parse_leaf(b, root_node);

	root_node->child_list = r_list_new();

	for (i = 0; i < tree_nodes; i++) {
		RFlirtNode *node = R_NEW0(RFlirtNode);
		node->length = read_byte(b);

		if (node->length < 0x10)
			node->mask = read_shift(b);
		else if (node->length <= 0x20)
			node->mask = r_flirt_explode_mask(b);
		else if (node->length <= 0x40)
			node->mask = (ut64)r_flirt_explode_mask(b) << 32 | r_flirt_explode_mask(b);

		bitmap = 1ULL << (node->length - 1);

		node->match = malloc(node->length);
		node->maskp = malloc(node->length);

		for (j = 0; bitmap; j++, bitmap >>= 1) {
			node->maskp[j] = (node->mask&bitmap) ? 0x00 : 0xff;
			node->match[j] = (node->mask&bitmap) ? 0x00 : read_byte(b);
		}
		r_list_append(root_node->child_list, node);

		r_flirt_parse_tree(b, node);
	}
}

R_API int r_flirt_parse (RIO *io, const char *filename) {
	FILE *fp;
	idasig_t *header;
	char *name;
	ut8 *buf, *decompressed_buf;
	int size, decompressed_size;

	fp = r_sandbox_fopen(filename, "rb");
	if (!fp) {
		eprintf ("Could not open \"%s\"", filename);
		return R_FALSE;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	header = R_NEW0(idasig_t);
	if (!header)
		goto err_exit;

	fread(header, 1, sizeof(idasig_t), fp);

	if (memcmp(header->magic, "IDASGN", 6))
		goto err_exit;

	if (header->version < 4 || header->version > 9) {
		eprintf("Unsupported flirt signature version\n");
		goto err_exit;
	}

	if (header->version > 7) {
		idasig_v8_t v8;
		fread(&v8, 1, sizeof(idasig_v8_t), fp);
		header->modules = v8.modules;
		if (v8.pattern_size > 0x40)
			goto err_exit;
	}
	else if (header->version > 5) {
		idasig_v6_t v6;
		fread(&v6, 1, sizeof(idasig_v6_t), fp);
		header->modules = v6.modules;
	}

	name = malloc(header->name_len + 1);
	if (!name)
		goto err_exit;

	fread(name, 1, header->name_len, fp);
	name[header->name_len] = '\0';

	eprintf("Loading %s\n", filename);
	eprintf("\"%s\"\n", name);
	eprintf("version %i flags %04x\n", header->version, header->flags);

	free(name);

	size -= ftell(fp);

	buf = malloc(size);
	if (!buf)
		goto err_exit;

	fread(buf, 1, size, fp);

	if (header->flags & IDASIG__FEATURE__COMPRESSED) {
		if ((decompressed_buf = r_gunzip(buf, size, &decompressed_size)) == NULL) {
			goto err_exit;
		}

		free(buf);
		buf = decompressed_buf;
		size = decompressed_size;
	}

	RFlirtNode *node = R_NEW0(RFlirtNode);
	node->child_list = r_list_new();
	bb *b = init_bb(buf, size);
	r_flirt_parse_tree(b, node);
	/*r_flirt_node_print(node, -1);*/

	const unsigned int buffer_size = r_io_size (io);
	ut8 *buffer = malloc (buffer_size);
	r_io_read_at (io, 0L, buffer, buffer_size);
	RListIter *it;
	RFlirtNode *n;
	r_cons_break(NULL, NULL);
	r_list_foreach(node->child_list, it, n) {
		r_flirt_node_match_buf(0L, buffer, buffer_size, n);
	}
	free(buffer);
	r_cons_break_end ();

	r_flirt_node_free(node);
	free(buf);
	free(b);
	free(header);
	fclose(fp);
	return R_TRUE;

err_exit:
	free(header);
	fclose(fp);
	return R_FALSE;
}
