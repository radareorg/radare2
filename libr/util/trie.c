/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util/r_trie.h>
#include <r_util.h>

typedef struct r_trie_node_t {
	ut8 *segment;
	void *value;
	struct r_trie_node_t **children;
	struct r_trie_node_t *parent;
	size_t segment_len;
	size_t children_count;
	size_t children_capacity;
} RTrieNode;

struct r_trie_t {
	RTrieNode *root;
	RTrieFree free_value;
	size_t size;
};

typedef struct {
	char *bytes;
	size_t length;
	size_t capacity;
	bool failed;
} RTrieKey;

static RTrieNode *trie_node_new(RStrs segment, void *value) {
	RTrieNode *node = R_NEW0 (RTrieNode);
	node->segment_len = r_strs_len (segment);
	if (node->segment_len) {
		node->segment = malloc (node->segment_len);
		if (!node->segment) {
			free (node);
			return NULL;
		}
		memcpy (node->segment, segment.a, node->segment_len);
	}
	node->value = value;
	return node;
}

static void trie_node_free_shallow(RTrieNode *node) {
	free (node->segment);
	free (node->children);
	free (node);
}

// Iterative destruction avoids exhausting the stack on deep tries.
static size_t trie_node_free(RTrieNode *node, RTrieFree free_value) {
	RTrieNode *stop = node->parent;
	size_t values = 0;
	while (node != stop) {
		if (node->children_count) {
			node = node->children[--node->children_count];
		} else {
			RTrieNode *parent = node->parent;
			if (node->value) {
				values++;
				if (free_value) {
					free_value (node->value);
				}
			}
			trie_node_free_shallow (node);
			node = parent;
		}
	}
	return values;
}

static bool trie_node_find_child(const RTrieNode *node, ut8 first, size_t *index) {
	size_t lo = 0;
	size_t hi = node->children_count;
	while (lo < hi) {
		size_t mid = lo + ((hi - lo) / 2);
		ut8 current = node->children[mid]->segment[0];
		if (current < first) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	*index = lo;
	return lo < node->children_count && node->children[lo]->segment[0] == first;
}

static RTrieNode *trie_node_find_match(const RTrieNode *node, const char *key, size_t key_len, size_t *index) {
	if (!trie_node_find_child (node, (ut8)key[0], index)) {
		return NULL;
	}
	RTrieNode *child = node->children[*index];
	if (child->segment_len > key_len || memcmp (child->segment, key, child->segment_len)) {
		return NULL;
	}
	return child;
}

static bool trie_node_insert_child(RTrieNode *node, size_t index, RTrieNode *child) {
	if (node->children_count == node->children_capacity) {
		/* children have distinct first bytes, so capacity never exceeds 256 */
		size_t capacity = node->children_capacity? node->children_capacity * 2: 4;
		RTrieNode **children = realloc (node->children, capacity * sizeof (RTrieNode *));
		if (!children) {
			return false;
		}
		node->children = children;
		node->children_capacity = capacity;
	}
	memmove (node->children + index + 1, node->children + index,
		(node->children_count - index) * sizeof (RTrieNode *));
	node->children[index] = child;
	child->parent = node;
	node->children_count++;
	return true;
}

static size_t trie_common_prefix(const RTrieNode *node, RStrs key) {
	size_t common = 0;
	size_t key_len = r_strs_len (key);
	size_t limit = R_MIN (node->segment_len, key_len);
	while (common < limit && node->segment[common] == (ut8)key.a[common]) {
		common++;
	}
	return common;
}

static bool trie_key_append(RTrieKey *key, const ut8 *bytes, size_t length) {
	if (!length) {
		return true;
	}
	if (length > SZT_MAX - key->length) {
		return false;
	}
	size_t needed = key->length + length;
	if (needed > key->capacity) {
		size_t capacity = key->capacity? key->capacity: 64;
		while (capacity < needed) {
			if (capacity > SZT_MAX / 2) {
				capacity = needed;
				break;
			}
			capacity *= 2;
		}
		char *resized = realloc (key->bytes, capacity);
		if (!resized) {
			return false;
		}
		key->bytes = resized;
		key->capacity = capacity;
	}
	memcpy (key->bytes + key->length, bytes, length);
	key->length = needed;
	return true;
}

static RTrieNode *trie_find_prefix_node(const RTrie *trie, RStrs prefix, RTrieKey *key) {
	RTrieNode *node = trie->root;
	size_t prefix_len = r_strs_len (prefix);
	size_t offset = 0;
	while (offset < prefix_len) {
		size_t index;
		if (!trie_node_find_child (node, (ut8)prefix.a[offset], &index)) {
			return NULL;
		}
		RTrieNode *child = node->children[index];
		size_t remaining = prefix_len - offset;
		size_t common = R_MIN (child->segment_len, remaining);
		if (memcmp (child->segment, prefix.a + offset, common)) {
			return NULL;
		}
		if (key && !trie_key_append (key, child->segment, child->segment_len)) {
			key->failed = true;
			return NULL;
		}
		node = child;
		if (remaining <= child->segment_len) {
			return node;
		}
		offset += child->segment_len;
	}
	return node;
}

R_API RTrie *r_trie_new(RTrieFree free_value) {
	RTrie *trie = R_NEW0 (RTrie);
	RTrieNode *root = R_NEW0 (RTrieNode);
	trie->root = root;
	trie->free_value = free_value;
	return trie;
}

R_API void r_trie_free(RTrie *trie) {
	if (trie) {
		trie_node_free (trie->root, trie->free_value);
		free (trie);
	}
}

R_API size_t r_trie_size(const RTrie *trie) {
	R_RETURN_VAL_IF_FAIL (trie, 0);
	return trie->size;
}

R_API bool r_trie_insert(RTrie *trie, RStrs key, void *value) {
	R_RETURN_VAL_IF_FAIL (trie && key.a && key.b >= key.a && value, false);
	RTrieNode *node = trie->root;
	size_t key_len = r_strs_len (key);
	size_t offset = 0;
	while (offset < key_len) {
		size_t index;
		if (!trie_node_find_child (node, (ut8)key.a[offset], &index)) {
			RTrieNode *leaf = trie_node_new (r_strs_sub (key, offset, key_len), value);
			if (!leaf || !trie_node_insert_child (node, index, leaf)) {
				if (leaf) {
					trie_node_free_shallow (leaf);
				}
				return false;
			}
			trie->size++;
			return true;
		}
		RTrieNode *child = node->children[index];
		size_t common = trie_common_prefix (child, r_strs_sub (key, offset, key_len));
		if (common == child->segment_len) {
			offset += common;
			node = child;
			continue;
		}
		RTrieNode *middle = trie_node_new (r_strs_from_len ((const char *)child->segment, common), NULL);
		if (!middle) {
			return false;
		}
		size_t key_suffix_len = key_len - offset - common;
		RTrieNode *leaf = NULL;
		if (key_suffix_len) {
			leaf = trie_node_new (r_strs_sub (key, offset + common, key_len), value);
		} else {
			middle->value = value;
		}
		middle->children_capacity = key_suffix_len? 2: 1;
		middle->children = malloc (middle->children_capacity * sizeof (RTrieNode *));
		if (!middle->children || (key_suffix_len && !leaf)) {
			if (leaf) {
				trie_node_free_shallow (leaf);
			}
			trie_node_free_shallow (middle);
			return false;
		}
		child->segment_len -= common;
		memmove (child->segment, child->segment + common, child->segment_len);
		ut8 *shrunk = realloc (child->segment, child->segment_len);
		if (shrunk) {
			/* on failure the over-allocated buffer stays, which is still valid */
			child->segment = shrunk;
		}
		if (leaf && leaf->segment[0] < child->segment[0]) {
			middle->children[0] = leaf;
			middle->children[1] = child;
		} else {
			middle->children[0] = child;
			if (leaf) {
				middle->children[1] = leaf;
			}
		}
		child->parent = middle;
		if (leaf) {
			leaf->parent = middle;
		}
		middle->children_count = middle->children_capacity;
		middle->parent = node;
		node->children[index] = middle;
		trie->size++;
		return true;
	}
	if (node->value) {
		if (node->value != value && trie->free_value) {
			trie->free_value (node->value);
		}
	} else {
		trie->size++;
	}
	node->value = value;
	return true;
}

R_API void *r_trie_find_longest_prefix(const RTrie *trie, RStrs input, R_OUT size_t *matched_len) {
	R_RETURN_VAL_IF_FAIL (trie && input.a && input.b >= input.a && matched_len, NULL);
	RTrieNode *node = trie->root;
	void *best = node->value;
	size_t input_len = r_strs_len (input);
	size_t offset = 0;
	*matched_len = 0;
	while (offset < input_len) {
		size_t index;
		RTrieNode *child = trie_node_find_match (node, input.a + offset, input_len - offset, &index);
		if (!child) {
			break;
		}
		offset += child->segment_len;
		node = child;
		if (node->value) {
			best = node->value;
			*matched_len = offset;
		}
	}
	return best;
}

R_API void *r_trie_find(const RTrie *trie, RStrs key) {
	R_RETURN_VAL_IF_FAIL (trie && key.a && key.b >= key.a, NULL);
	size_t matched;
	void *value = r_trie_find_longest_prefix (trie, key, &matched);
	return (matched == r_strs_len (key))? value: NULL;
}

R_API bool r_trie_foreach_prefix(const RTrie *trie, RStrs prefix, RTrieForeachCb callback, void *user) {
	R_RETURN_VAL_IF_FAIL (trie && prefix.a && prefix.b >= prefix.a && callback, false);
	RTrieKey key = { 0 };
	RTrieNode *node = trie_find_prefix_node (trie, prefix, &key);
	if (!node) {
		free (key.bytes);
		return !key.failed;
	}
	RTrieNode *root = node;
	for (;;) {
		const char *bytes = key.bytes? key.bytes: "";
		if (node->value && !callback (r_strs_from_len (bytes, key.length), node->value, user)) {
			free (key.bytes);
			return false;
		}
		if (node->children_count) {
			node = node->children[0];
			if (!trie_key_append (&key, node->segment, node->segment_len)) {
				free (key.bytes);
				return false;
			}
			continue;
		}
		while (node != root) {
			RTrieNode *parent = node->parent;
			size_t index;
			trie_node_find_child (parent, node->segment[0], &index);
			key.length -= node->segment_len;
			if (++index < parent->children_count) {
				node = parent->children[index];
				if (!trie_key_append (&key, node->segment, node->segment_len)) {
					free (key.bytes);
					return false;
				}
				break;
			}
			node = parent;
		}
		if (node == root) {
			break;
		}
	}
	free (key.bytes);
	return true;
}

static void trie_node_compact_child(RTrieNode *node, size_t index) {
	RTrieNode *child = node->children[index];
	if (child->value || child->children_count > 1) {
		return;
	}
	if (child->children_count == 0) {
		memmove (node->children + index, node->children + index + 1,
			(--node->children_count - index) * sizeof (RTrieNode *));
		trie_node_free_shallow (child);
		return;
	}
	RTrieNode *grandchild = child->children[0];
	/* both segments are live buffers, so their sum cannot overflow size_t */
	size_t merged_len = child->segment_len + grandchild->segment_len;
	ut8 *segment = realloc (child->segment, merged_len);
	if (!segment) {
		return;
	}
	memcpy (segment + child->segment_len, grandchild->segment, grandchild->segment_len);
	child->segment = segment;
	child->segment_len = merged_len;
	child->value = grandchild->value;
	free (child->children);
	child->children = grandchild->children;
	child->children_count = grandchild->children_count;
	child->children_capacity = grandchild->children_capacity;
	size_t i;
	for (i = 0; i < child->children_count; i++) {
		child->children[i]->parent = child;
	}
	free (grandchild->segment);
	free (grandchild);
}

R_API void *r_trie_take(RTrie *trie, RStrs key) {
	R_RETURN_VAL_IF_FAIL (trie && key.a && key.b >= key.a, NULL);
	RTrieNode *node = trie->root;
	RTrieNode *parent = NULL;
	RTrieNode *grandparent = NULL;
	size_t node_index = 0;
	size_t parent_index = 0;
	size_t key_len = r_strs_len (key);
	size_t offset = 0;
	while (offset < key_len) {
		size_t index;
		RTrieNode *child = trie_node_find_match (node, key.a + offset, key_len - offset, &index);
		if (!child) {
			return NULL;
		}
		grandparent = parent;
		parent_index = node_index;
		parent = node;
		node_index = index;
		offset += child->segment_len;
		node = child;
	}
	void *value = node->value;
	if (!value) {
		return NULL;
	}
	node->value = NULL;
	trie->size--;
	/* compacting the two deepest levels is enough: removing an emptied leaf can
	 * leave `parent` valueless with one child, but merges never cascade upward */
	if (parent) {
		trie_node_compact_child (parent, node_index);
		if (grandparent) {
			trie_node_compact_child (grandparent, parent_index);
		}
	}
	return value;
}

R_API bool r_trie_delete(RTrie *trie, RStrs key) {
	R_RETURN_VAL_IF_FAIL (trie, false);
	void *value = r_trie_take (trie, key);
	if (!value) {
		return false;
	}
	if (trie->free_value) {
		trie->free_value (value);
	}
	return true;
}

R_API size_t r_trie_delete_prefix(RTrie *trie, RStrs prefix) {
	R_RETURN_VAL_IF_FAIL (trie && prefix.a && prefix.b >= prefix.a, 0);
	if (r_strs_empty (prefix)) {
		RTrieNode *root = R_NEW0 (RTrieNode);
		size_t removed = trie_node_free (trie->root, trie->free_value);
		trie->root = root;
		trie->size = 0;
		return removed;
	}
	RTrieNode *node = trie_find_prefix_node (trie, prefix, NULL);
	if (!node) {
		return 0;
	}
	RTrieNode *parent = node->parent;
	size_t index;
	trie_node_find_child (parent, node->segment[0], &index);
	memmove (parent->children + index, parent->children + index + 1,
		(--parent->children_count - index) * sizeof (RTrieNode *));
	size_t removed = trie_node_free (node, trie->free_value);
	trie->size -= removed;
	node = parent;
	while (node->parent) {
		parent = node->parent;
		trie_node_find_child (parent, node->segment[0], &index);
		trie_node_compact_child (parent, index);
		node = parent;
	}
	return removed;
}
