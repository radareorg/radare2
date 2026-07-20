/* radare - LGPL - Copyright 2026 - pancake */

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

static void trie_node_free(RTrieNode *node, RTrieFree free_value) {
	size_t i;
	for (i = 0; i < node->children_count; i++) {
		trie_node_free (node->children[i], free_value);
	}
	if (node->value && free_value) {
		free_value (node->value);
	}
	trie_node_free_shallow (node);
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
		size_t capacity = 4;
		size_t alloc_size;
		if ((node->children_capacity && r_mul_overflow (node->children_capacity, (size_t)2, &capacity)) ||
			r_mul_overflow (capacity, sizeof (RTrieNode *), &alloc_size)) {
			return false;
		}
		RTrieNode **children = realloc (node->children, alloc_size);
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
	trie->root = trie_node_new (r_strs_from_len (NULL, 0), NULL);
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
		RStrs remaining = r_strs_sub (key, offset, key_len);
		size_t common = trie_common_prefix (child, remaining);
		if (common == child->segment_len) {
			offset += common;
			node = child;
			continue;
		}

		RTrieNode *middle = trie_node_new (r_strs_from_len ((const char *)child->segment, common), NULL);
		size_t child_suffix_len = child->segment_len - common;
		ut8 *child_suffix = malloc (child_suffix_len);
		if (!middle || !child_suffix) {
			if (middle) {
				trie_node_free_shallow (middle);
			}
			free (child_suffix);
			return false;
		}
		memcpy (child_suffix, child->segment + common, child_suffix_len);
		size_t key_suffix_offset = offset + common;
		size_t key_suffix_len = key_len - key_suffix_offset;
		RTrieNode *leaf = NULL;
		if (key_suffix_len) {
			leaf = trie_node_new (r_strs_sub (key, key_suffix_offset, key_len), value);
			if (!leaf) {
				free (child_suffix);
				trie_node_free_shallow (middle);
				return false;
			}
		} else {
			middle->value = value;
		}
		middle->children_capacity = leaf? 2: 1;
		middle->children = malloc (middle->children_capacity * sizeof (RTrieNode *));
		if (!middle->children) {
			if (leaf) {
				trie_node_free_shallow (leaf);
			}
			free (child_suffix);
			trie_node_free_shallow (middle);
			return false;
		}
		if (leaf && leaf->segment[0] < child_suffix[0]) {
			middle->children[0] = leaf;
			middle->children[1] = child;
		} else {
			middle->children[0] = child;
			if (leaf) {
				middle->children[1] = leaf;
			}
		}
		middle->children_count = middle->children_capacity;
		free (child->segment);
		child->segment = child_suffix;
		child->segment_len = child_suffix_len;
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

static RTrieNode *trie_find_node(const RTrie *trie, RStrs key) {
	RTrieNode *node = trie->root;
	size_t key_len = r_strs_len (key);
	size_t offset = 0;
	while (offset < key_len) {
		size_t index;
		RTrieNode *child = trie_node_find_match (node, key.a + offset, key_len - offset, &index);
		if (!child) {
			return NULL;
		}
		offset += child->segment_len;
		node = child;
	}
	return node;
}

R_API void *r_trie_find(const RTrie *trie, RStrs key) {
	R_RETURN_VAL_IF_FAIL (trie && key.a && key.b >= key.a, NULL);
	RTrieNode *node = trie_find_node (trie, key);
	return node? node->value: NULL;
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

static void trie_node_remove_child(RTrieNode *node, size_t index) {
	memmove (node->children + index, node->children + index + 1,
		(node->children_count - index - 1) * sizeof (RTrieNode *));
	node->children_count--;
}

static void trie_node_compact_child(RTrieNode *node, size_t index) {
	RTrieNode *child = node->children[index];
	if (child->value) {
		return;
	}
	if (child->children_count == 0) {
		trie_node_remove_child (node, index);
		trie_node_free_shallow (child);
		return;
	}
	if (child->children_count > 1) {
		return;
	}
	RTrieNode *grandchild = child->children[0];
	size_t merged_len;
	if (r_add_overflow (child->segment_len, grandchild->segment_len, &merged_len)) {
		return;
	}
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

static void *trie_node_take(RTrie *trie, RTrieNode *node, RStrs key, size_t offset) {
	size_t key_len = r_strs_len (key);
	if (offset == key_len) {
		void *value = node->value;
		if (value) {
			node->value = NULL;
			trie->size--;
		}
		return value;
	}
	size_t index;
	RTrieNode *child = trie_node_find_match (node, key.a + offset, key_len - offset, &index);
	if (!child) {
		return NULL;
	}
	void *value = trie_node_take (trie, child, key, offset + child->segment_len);
	if (value) {
		trie_node_compact_child (node, index);
	}
	return value;
}

R_API void *r_trie_take(RTrie *trie, RStrs key) {
	R_RETURN_VAL_IF_FAIL (trie && key.a && key.b >= key.a, NULL);
	return trie_node_take (trie, trie->root, key, 0);
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
