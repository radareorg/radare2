/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util/r_trie.h>
#include <r_util.h>

typedef struct r_trie_node_t {
	ut8 *segment;
	size_t segment_len;
	void *value;
	struct r_trie_node_t **children;
	size_t children_count;
	size_t children_capacity;
} RTrieNode;

struct r_trie_t {
	RTrieNode *root;
	RTrieFree free_value;
	size_t size;
};

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

/* Iterative destruction: `segment` is repurposed as a parent link so that
 * arbitrarily deep tries cannot exhaust the stack. */
static void trie_node_free(RTrieNode *node, RTrieFree free_value) {
	free (node->segment);
	node->segment = NULL;
	while (node) {
		if (node->children_count) {
			RTrieNode *child = node->children[--node->children_count];
			free (child->segment);
			child->segment = (ut8 *)node;
			node = child;
		} else {
			RTrieNode *parent = (RTrieNode *)node->segment;
			if (node->value && free_value) {
				free_value (node->value);
			}
			free (node->children);
			free (node);
			node = parent;
		}
	}
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
		middle->children_count = middle->children_capacity;
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
