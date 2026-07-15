/* radare - LGPL - Copyright 2026 - pancake */

#define GRES_SECTION_PREFIX ".gresource."
#define GRES_HEADER_SIZE 24
#define GRES_HASH_HEADER_SIZE 8
#define GRES_HASH_ITEM_SIZE 24
#define GRES_VALUE_HEADER_SIZE 8
#define GRES_VARIANT_TYPE "(uuay)"
#define GRES_VARIANT_TRAILER_SIZE (sizeof (GRES_VARIANT_TYPE))
#define GRES_FLAG_COMPRESSED 1

typedef struct {
	RBuffer *buf;
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	const char *origin;
} GResCtx;

typedef struct {
	ut32 parent;
	ut32 key_start;
	ut16 key_size;
	ut8 type;
	ut32 value_start;
	ut32 value_end;
} GResItem;

typedef struct {
	const char *name;
	size_t item;
} GResLeaf;

static bool gres_read(const GResCtx *ctx, ut64 offset, void *dst, size_t size) {
	if (offset > ctx->size || size > ctx->size - offset || offset > UT64_MAX - ctx->paddr) {
		return false;
	}
	return r_buf_read_at (ctx->buf, ctx->paddr + offset, dst, size) == size;
}

static bool gres_read_item(const GResCtx *ctx, ut64 offset, GResItem *item) {
	ut8 buf[GRES_HASH_ITEM_SIZE];
	if (!gres_read (ctx, offset, buf, sizeof (buf))) {
		return false;
	}
	item->parent = r_read_le32 (buf + 4);
	item->key_start = r_read_le32 (buf + 8);
	item->key_size = r_read_le16 (buf + 12);
	item->type = buf[14];
	item->value_start = r_read_le32 (buf + 16);
	item->value_end = r_read_le32 (buf + 20);
	return true;
}

static char *gres_item_name(const GResCtx *ctx, const GResItem *item, const char *parent, size_t *names_size) {
	size_t parent_size = parent? strlen (parent): 0;
	size_t name_size;
	if (item->key_start > ctx->size || item->key_size > ctx->size - item->key_start
		|| r_add_overflow (parent_size, (size_t)item->key_size, &name_size)
		|| name_size >= ALLOC_SIZE_LIMIT || *names_size > ALLOC_SIZE_LIMIT - name_size - 1) {
		return NULL;
	}
	char *name = malloc (name_size + 1);
	if (!name) {
		return NULL;
	}
	if (parent_size) {
		memcpy (name, parent, parent_size);
	}
	if (!gres_read (ctx, item->key_start, name + parent_size, item->key_size)
		|| memchr (name + parent_size, 0, item->key_size)) {
		free (name);
		return NULL;
	}
	name[name_size] = 0;
	*names_size += name_size + 1;
	return name;
}

static bool gres_build_names(const GResCtx *ctx, const GResItem *items, size_t n_items, char **names) {
	if (!n_items) {
		return true;
	}
	ut8 *status = calloc (n_items, sizeof (ut8));
	size_t stack_size;
	if (r_mul_overflow (n_items, sizeof (size_t), &stack_size)) {
		free (status);
		return false;
	}
	size_t *stack = malloc (stack_size);
	if (!status || !stack) {
		free (status);
		free (stack);
		return false;
	}
	size_t names_size = 0;
	size_t i;
	for (i = 0; i < n_items; i++) {
		if (status[i]) {
			continue;
		}
		size_t depth = 0;
		size_t current = i;
		bool valid = true;
		while (true) {
			if (current >= n_items || status[current] == 2 || status[current] == 3) {
				valid = false;
				break;
			}
			if (status[current] == 1) {
				break;
			}
			status[current] = 3;
			stack[depth++] = current;
			ut32 parent = items[current].parent;
			if (parent == UT32_MAX) {
				break;
			}
			current = parent;
		}
		while (depth) {
			current = stack[--depth];
			ut32 parent = items[current].parent;
			const char *parent_name = NULL;
			if (parent != UT32_MAX) {
				if (parent >= n_items || status[parent] != 1) {
					valid = false;
				} else {
					parent_name = names[parent];
				}
			}
			if (valid) {
				names[current] = gres_item_name (ctx, &items[current], parent_name, &names_size);
				valid = names[current] != NULL;
			}
			status[current] = valid? 1: 2;
		}
	}
	free (status);
	free (stack);
	return true;
}

static int gres_leaf_cmp(const void *a, const void *b) {
	const GResLeaf *la = a;
	const GResLeaf *lb = b;
	return strcmp (la->name, lb->name);
}

static bool gres_add_resource(RVecRBinResource *resources, const char *name, const char *type,
		const char *origin, ut64 paddr, ut64 vaddr, ut64 size) {
	size_t index = RVecRBinResource_length (resources);
	if (index > UT32_MAX) {
		return false;
	}
	RBinResource *resource = RVecRBinResource_emplace_back (resources);
	if (!resource) {
		return false;
	}
	resource->name = strdup (name);
	resource->type = strdup (type);
	resource->origin = origin? strdup (origin): NULL;
	resource->paddr = paddr;
	resource->vaddr = vaddr;
	resource->size = size;
	resource->id = UT64_MAX;
	resource->index = index;
	resource->type_id = UT32_MAX;
	resource->language_id = UT32_MAX;
	resource->named = true;
	return resource->name && resource->type && (!origin || resource->origin);
}

static bool gres_add_value(const GResCtx *ctx, const GResItem *item, const char *name, RVecRBinResource *resources) {
	if (item->value_start > item->value_end || item->value_end > ctx->size
		|| item->value_start & 7) {
		return true;
	}
	ut64 value_size = item->value_end - item->value_start;
	if (value_size < GRES_VALUE_HEADER_SIZE + GRES_VARIANT_TRAILER_SIZE) {
		return true;
	}
	ut8 trailer[GRES_VARIANT_TRAILER_SIZE];
	ut64 trailer_offset = item->value_end - sizeof (trailer);
	if (!gres_read (ctx, trailer_offset, trailer, sizeof (trailer)) || trailer[0]
		|| memcmp (trailer + 1, GRES_VARIANT_TYPE, sizeof (GRES_VARIANT_TYPE) - 1)) {
		return true;
	}
	ut8 header[GRES_VALUE_HEADER_SIZE];
	if (!gres_read (ctx, item->value_start, header, sizeof (header))) {
		return true;
	}
	ut32 logical_size = r_read_le32 (header);
	ut32 flags = r_read_le32 (header + 4);
	if (flags & ~GRES_FLAG_COMPRESSED) {
		return true;
	}
	ut64 data_offset = item->value_start + GRES_VALUE_HEADER_SIZE;
	ut64 data_size = value_size - GRES_VALUE_HEADER_SIZE - GRES_VARIANT_TRAILER_SIZE;
	const char *type = "gresource-compressed";
	if (!(flags & GRES_FLAG_COMPRESSED)) {
		ut8 terminator;
		if (!data_size || logical_size != data_size - 1
			|| !gres_read (ctx, data_offset + logical_size, &terminator, 1) || terminator) {
			return true;
		}
		data_size = logical_size;
		type = "gresource";
	}
	if (data_offset > UT64_MAX - ctx->paddr || data_offset > UT64_MAX - ctx->vaddr) {
		return true;
	}
	return gres_add_resource (resources, name, type, ctx->origin,
		ctx->paddr + data_offset, ctx->vaddr + data_offset, data_size);
}

static bool gres_parse_section(RBinFile *bf, const RBinSection *section, RVecRBinResource *resources) {
	GResCtx ctx = {
		.buf = bf->buf,
		.paddr = section->paddr,
		.vaddr = section->vaddr,
		.size = section->size,
		.origin = section->name,
	};
	ut8 header[GRES_HEADER_SIZE];
	if (!gres_read (&ctx, 0, header, sizeof (header))
		|| (memcmp (header, "GVariant", 8) && memcmp (header, "raVGtnai", 8))
		|| r_read_le32 (header + 8)) {
		return true;
	}
	ut32 root_start = r_read_le32 (header + 16);
	ut32 root_end = r_read_le32 (header + 20);
	if (root_start < GRES_HEADER_SIZE || root_start & 3 || root_start > root_end
		|| root_end > ctx.size || root_end - root_start < GRES_HASH_HEADER_SIZE
		|| root_end - root_start > ALLOC_SIZE_LIMIT) {
		return true;
	}
	ut8 hash_header[GRES_HASH_HEADER_SIZE];
	if (!gres_read (&ctx, root_start, hash_header, sizeof (hash_header))) {
		return true;
	}
	ut64 n_bloom_words = r_read_le32 (hash_header) & 0x7ffffff;
	ut64 n_buckets = r_read_le32 (hash_header + 4);
	ut64 bloom_size;
	ut64 buckets_size;
	if (r_mul_overflow (n_bloom_words, (ut64)4, &bloom_size)
		|| r_mul_overflow (n_buckets, (ut64)4, &buckets_size)) {
		return true;
	}
	ut64 items_offset = root_start + GRES_HASH_HEADER_SIZE;
	if (bloom_size > root_end - items_offset) {
		return true;
	}
	items_offset += bloom_size;
	if (buckets_size > root_end - items_offset) {
		return true;
	}
	items_offset += buckets_size;
	ut64 items_size = root_end - items_offset;
	if (items_size % GRES_HASH_ITEM_SIZE) {
		return true;
	}
	ut64 n_items64 = items_size / GRES_HASH_ITEM_SIZE;
	if (n_items64 > SIZE_MAX) {
		return true;
	}
	size_t n_items = n_items64;
	size_t items_alloc;
	size_t names_alloc;
	size_t leaves_alloc;
	if (r_mul_overflow (n_items, sizeof (GResItem), &items_alloc)
		|| r_mul_overflow (n_items, sizeof (char *), &names_alloc)
		|| r_mul_overflow (n_items, sizeof (GResLeaf), &leaves_alloc)) {
		return false;
	}
	GResItem *items = n_items? calloc (1, items_alloc): NULL;
	char **names = n_items? calloc (1, names_alloc): NULL;
	GResLeaf *leaves = n_items? calloc (1, leaves_alloc): NULL;
	if ((n_items && (!items || !names || !leaves))) {
		free (items);
		free (names);
		free (leaves);
		return false;
	}
	bool ok = true;
	size_t i;
	for (i = 0; i < n_items; i++) {
		if (!gres_read_item (&ctx, items_offset + i * GRES_HASH_ITEM_SIZE, &items[i])) {
			ok = false;
			break;
		}
	}
	if (ok) {
		ok = gres_build_names (&ctx, items, n_items, names);
	}
	size_t n_leaves = 0;
	if (ok) {
		for (i = 0; i < n_items; i++) {
			if (items[i].type == 'v' && names[i] && names[i][0] == '/') {
				leaves[n_leaves].name = names[i];
				leaves[n_leaves++].item = i;
			}
		}
		if (n_leaves > 1) {
			qsort (leaves, n_leaves, sizeof (GResLeaf), gres_leaf_cmp);
		}
		ok = gres_add_resource (resources, section->name, "gresource-bundle", NULL,
			section->paddr, section->vaddr, section->size);
	}
	for (i = 0; ok && i < n_leaves; i++) {
		ok = gres_add_value (&ctx, &items[leaves[i].item], leaves[i].name, resources);
	}
	for (i = 0; i < n_items; i++) {
		free (names[i]);
	}
	free (items);
	free (names);
	free (leaves);
	return ok;
}

bool Elf_(load_gresources)(RBinFile *bf, ELFOBJ *eo, RVecRBinResource *resources) {
	R_RETURN_VAL_IF_FAIL (bf && bf->buf && eo && resources, false);
	const RVecRBinSection *sections = Elf_(load_sections) (bf, eo);
	if (!sections) {
		return false;
	}
	RBinSection *section;
	R_VEC_FOREACH (sections, section) {
		if (section->name && r_str_startswith (section->name, GRES_SECTION_PREFIX)
			&& section->size && !gres_parse_section (bf, section, resources)) {
			return false;
		}
	}
	return true;
}
