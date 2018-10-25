#include <stdlib.h>
#include "r_util/r_trie.h"

static int c2_idx(char c) {
	if (c <= 'Z' && c >= 'A') {
		return c - 'A';
	}
	if (c <= 'z' && c >= 'a') {
		return c - 'a' + 26;
	}
	if (c <= '9' && c >= '0') {
		return c - '0' + 26 * 2;
	}
	return 26*2 + 10;
}

static RTrieNode *r_trie_new_node() {
	RTrieNode *n = R_NEW0 (RTrieNode);
	if (!n) {
		return NULL;
	}
	int i;
	for (i = 0; i < ALPHABET_SIZE; i++){
		n->child[i] = NULL;
	}
	n->is_leaf = 0;
	return n;
}

static RTrieNode *r_trie_node_insert(RTrieNode *n, char *name, void *f) {
	if (!n) {
		n = r_trie_new_node ();
	}
	if (!*name) {
		n->data = f;
		n->is_leaf = 1;
		return n;
	}
	const int idx = c2_idx (*name);
	n->child[idx] = r_trie_node_insert (n->child[idx], ++name, f);
	return n;
}

static void *r_trie_node_find(RTrieNode *n, char *name) {
	if (!n) {
		return NULL;
	}
	if (!name) {
		return NULL;
	}
	if (!*name) {
		if (n->is_leaf) {
			return n->data;
		} else {
			return NULL;
		}
	}
	const int idx = c2_idx (*name);
	return r_trie_node_find (n->child[idx], ++name);
}

static void r_trie_node_free(RTrieNode **n) {
	if (!n || *n) {
		return;
	}
	int i;
	for (i = 0; i < ALPHABET_SIZE; i++){
		r_trie_node_free (&(*n)->child[i]);
	}
	R_FREE (*n);
}

static bool r_trie_node_delete(RTrieNode **n, char *name) {
	if (!n) {
		return false;
	}
	if (!*n) {
		return false;
	}
	if (!name) {
		return false;
	}
	if (!*name) {
		if ((*n)->is_leaf) {
			(*n)->is_leaf = 0;
			int i;
			for (i = 0; i < ALPHABET_SIZE; i++) {
				if ((*n)->child[i]) {
					return true;
				}
			}
			r_trie_node_free (n);
			return true;
		} else {
			return false;
		}
	}
	const int idx = c2_idx (*name);
	const int result = r_trie_node_delete (&(*n)->child[idx], ++name);
	if (!result) {
		return false;
	}
	int i;
	for (i = 0; i < ALPHABET_SIZE; i++) {
		if ((*n)->child[i]) {
			return true;
		}
	}
	r_trie_node_free (n);
	return true;
}

R_API RTrie *r_trie_new() {
	RTrie * n = R_NEW0 (RTrie);
	if (!n) {
		return NULL;
	}
	n->root = r_trie_new_node ();
	if (!n->root) {
		R_FREE (n);
		return NULL;
	}
	return n;
}

R_API bool r_trie_insert(RTrie * t, char * name, void * f) {
	if (!t) {
		return false;
	}
	RTrieNode *tmp = r_trie_node_insert (t->root, name, f);
	if (!tmp) {
		return false;
	}
	t->root = tmp;
	return true;
}

R_API bool r_trie_update(RTrie * t, char * name, void * f) {
	return r_trie_insert (t, name, f);
}

R_API void *r_trie_find(RTrie * t, char * name) {
	if (!t) {
		return NULL;
	}
	return r_trie_node_find (t->root, name);
}

R_API void r_trie_free(RTrie ** t) {
	if (!t) {
		return;
	}
	if (!*t) {
		return;
	}
	if ((*t)->root) {
		r_trie_node_free (&(*t)->root);
	}
	R_FREE (*t);
}

R_API bool r_trie_delete(RTrie * t, char * name) {
	if (!t) {
		return false;
	}
	if (!t->root) {
		return false;
	}
	bool result = r_trie_node_delete (&t->root, name);
	return result;
}

/* Deletes 'name' and if the trie is empty frees and nulls it, 
	so it need to be reallocated next time we want to use it */
R_API bool r_trie_erase(RTrie ** t, char * name) {
	if (!t) {
		return false;
	}
	if (!*t) {
		return false;
	}
	if (!(*t)->root) {
		return false;
	}
	bool result = r_trie_node_delete (&(*t)->root, name);
	if (!(*t)->root) {
		r_trie_free (t);
	}
	return result;
}

