#ifndef R_TRIE_H
#define R_TRIE_H
#include "r_types.h"

#define ALPHABET_SIZE 63 // A-Z, a-z, 0-9 and _

typedef struct r_trie_node {
	struct r_trie_node * child[ALPHABET_SIZE];
	int is_leaf;
	void * data;
} RTrieNode;

typedef struct r_trie {
	RTrieNode *root;
} RTrie;

R_API RTrie *r_trie_new(void);
R_API bool r_trie_insert(RTrie * t, char * name, void * f);
R_API bool r_trie_update(RTrie * t, char * name, void * f);
R_API bool r_trie_delete(RTrie * t, char * name);
R_API bool r_trie_erase(RTrie ** t, char * name);
R_API void *r_trie_find(RTrie * t, char * name);
R_API void r_trie_free(RTrie ** t);
#endif
