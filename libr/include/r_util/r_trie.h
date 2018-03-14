#ifndef R_TRIE_H
#define R_TRIE_H
#include "r_types.h"

#define ALPHABET_SIZE 63 // A-Z, a-z, 0-9 and _

typedef struct r_trie_node {
	struct r_trie_node * child[ALPHABET_SIZE];
	int is_leaf;
	void * data;
} TrieNode;

typedef struct r_trie {
	TrieNode *root;
} Trie;

R_API Trie *r_trie_new(void);
R_API bool r_trie_insert(Trie * t, char * name, void * f);
R_API bool r_trie_update(Trie * t, char * name, void * f);
R_API bool r_trie_delete(Trie * t, char * name);
R_API void *r_trie_find(Trie * t, char * name);
R_API void r_trie_free(Trie * t);
#endif
