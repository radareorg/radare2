/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R_TRIE_H
#define R_TRIE_H

#include <r_types.h>
#include <r_util/r_strs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_trie_t RTrie;
typedef void (*RTrieFree)(void *value);

/* Keys are copied and may contain NUL bytes. Values must be non-NULL. After a
 * successful insertion the trie owns the value; replacing a key releases its
 * previous value with free_value. A failed insertion leaves ownership with the
 * caller. */
R_API RTrie *r_trie_new(RTrieFree free_value);
R_API void r_trie_free(RTrie *trie);
R_API size_t r_trie_size(const RTrie *trie);
R_API bool r_trie_insert(RTrie *trie, RStrs key, void *value);
R_API void *r_trie_find(const RTrie *trie, RStrs key);
R_API void *r_trie_find_longest_prefix(const RTrie *trie, RStrs input, R_OUT size_t *matched_len);
/* Removes a key and transfers ownership of its value to the caller. */
R_API void *r_trie_take(RTrie *trie, RStrs key);
R_API bool r_trie_delete(RTrie *trie, RStrs key);

#ifdef __cplusplus
}
#endif

#endif
