#include <stdlib.h>
#include "r_util/r_trie.h"

static int c2_idx(char c) {
	if (c <= 'Z' && c >= 'A') return c-'A';
	if (c <= 'z' && c >= 'a') return c-'a'+26;
	if (c <= '9' && c >= '0') return c-'0'+26*2;
	return 26*2 + 10;
}

static TrieNode *r_trie_new_node(){
	TrieNode *n = R_NEW0 (TrieNode);
	if (!n) return NULL;
	int i;
	for(i = 0; i < ALPHABET_SIZE; i++){
		n->child[i] = NULL;
	}
	n->is_leaf = 0;
	return n;
}

static TrieNode *r_trie_node_insert(TrieNode *n, char *name, void *f) {
	if (!n) {
		n = r_trie_new_node ();
	}
	if (*name=='\0') {
		n->data = f;
		n->is_leaf = 1;
		return n;
	}
	int idx = c2_idx (*name);
	n->child[idx] = r_trie_node_insert (n->child[idx], ++name, f);
	return n;
}

static void *r_trie_node_find(TrieNode *n, char *name) {
	if (!n) return NULL;
	if (*name=='\0' && n->is_leaf) return n->data;
	if (*name=='\0') return NULL;
	int idx = c2_idx (*name);
	return r_trie_node_find (n->child[idx], ++name);
}

static void r_trie_node_free(TrieNode *n){
	if (!n) return;
	int i;
	for(i = 0; i < ALPHABET_SIZE; i++){
		r_trie_node_free (n->child[i]);
	}
	free (n);
}

static bool r_trie_node_delete(TrieNode *n, char *name) {
	if (!n) return false;
	if (*name=='\0' && n->is_leaf){
		n->is_leaf = 0;
		int i;
		for (i=0; i<ALPHABET_SIZE; i++) {
			if (n->child[i]) {
				return true;
			}
		}
		r_trie_node_free (n);
		return true;
	}
	if (*name=='\0') return false;
	int idx = c2_idx (*name);
	r_trie_node_delete (n->child[idx], ++name);
	if(!n) return true;
	int i;
	for (i=0; i<ALPHABET_SIZE; i++) {
		if (n->child[i]) {
			return true;
		}
	}
	r_trie_node_free (n);
	return true;
}

R_API Trie *r_trie_new() {
	Trie * n = R_NEW0 (Trie);
	if (!n) return NULL;
	n->root = r_trie_new_node ();
	if (!n->root) return NULL;
	return n;
}

R_API bool r_trie_insert(Trie * t, char * name, void * f) {
	TrieNode *tmp = r_trie_node_insert (t->root, name, f);
	if (!tmp) return false;
	t->root = tmp;
	return true;
}

R_API bool r_trie_update(Trie * t, char * name, void * f) {
	return r_trie_insert (t, name, f);
}

R_API void *r_trie_find(Trie * t, char * name) {
	return r_trie_node_find (t->root, name);
}

R_API void r_trie_free(Trie * t) {
	if (!t) return;
	r_trie_node_free (t->root);
	free(t);
}

R_API bool r_trie_delete(Trie * t, char * name) {
	bool res = r_trie_node_delete (t->root, name);
	if (!t->root) r_trie_free (t);
	return res;
}

