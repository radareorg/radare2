/* radare - LGPL - Copyright 2017 - rkx1209 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "r_hashtable.h"

RHTable *r_htable_new(size_t size) {
	RHTable *htable;
	ut32 i;
	if (!size) {
		return NULL;
	}
	if ((htable = (RHTable *) malloc (sizeof(RHTable))) == NULL) {
		return NULL;
	}
	if ((htable->table = (RHTableIter **) malloc (sizeof(RHTableIter *) * size)) == NULL) {
		free (htable);
		return NULL;
	}
	for (i = 0; i < size; i++) {
		htable->table[i] = NULL;
	}
	htable->length = size;
	return htable;
}

void r_htable_clear(RHTable *htable) {
	size_t i;
	RHTableIter *entry, *next;
	for (i = 0; i < htable->length; i++) {
		entry = htable->table[i];
		while (entry) {
			next = entry->next;
			free (entry->key);
			free (entry);
			entry = next;
		}
		htable->table[i] = NULL;
	}
}

void r_htable_free(RHTable *htable) {
	r_htable_clear (htable);
	free (htable);
}

static unsigned long r_hash(RHTable *htable, char *key) {
	size_t i = 0;
	unsigned long hashval = 0;
	while (hashval < ULONG_MAX && i < strlen (key)) {
		hashval = hashval << 8;
		hashval += key[i];
		i++;
	}
	return hashval % htable->length;
}

RHTableIter *r_htable_entry_new(char *key, void *value) {
	RHTableIter *entry;
	if ((entry = malloc (sizeof(RHTableIter))) == NULL) {
		return NULL;
	}
	if ((entry->key = strdup (key)) == NULL) {
		free (entry);
		return NULL;
	}
	entry->data = value;
	entry->next = NULL;
	return entry;
}

bool r_htable_add(RHTable *htable, char *key, void *value) {
	unsigned long hash;
	RHTableIter *entry = NULL, *last = NULL, *newent = NULL;

	hash = r_hash (htable, key);
	entry = htable->table[hash];

	while (entry != NULL && strcmp (key, entry->key) < 0) {
		last = entry;
		entry = entry->next;
	}

	/* Replace exist element */
	if (entry != NULL && strcmp (key, entry->key) == 0) {
		entry->data = value;
		// printf ("exist ");
	} else {
		/* couldn't find it. add new one */
		newent = r_htable_entry_new (key, value);
		if (!newent) {
			return false;
		}
		/* not exist any elements */
		if (last == NULL) {
			htable->table[hash] = newent;
		} else if (last->next == NULL) {
			/* tail of linked list */
			last->next = newent;
		} else {
			/* middle of linker list */
			newent->next = last->next;
			last->next = newent;
		}
		// printf ("Add ");
	}
	return true;
}

bool r_htable_add_uint64(RHTable *htable, ut64 key, void *value) {
	char buf[32];
	sprintf (buf, "%llu", key);
	return r_htable_add (htable, buf, value);
}

void *r_htable_get(RHTable *htable, char *key) {
	RHTableIter *entry;
	unsigned long hash;
	hash = r_hash (htable, key);
	for (entry = htable->table[hash]; entry; entry = entry->next) {
		if (strcmp (entry->key, key) == 0) {
			return entry->data;
		}
	}
	return NULL;
}

void *r_htable_get_uint64(RHTable *htable, ut64 key) {
	char buf[32];
	sprintf (buf, "%llu", key);
	return r_htable_get (htable, buf);
}

#ifdef MAIN
struct test_value {
	ut64 addr;
	char *msg;
} a = {
	0x100, "Msg from 0x100"
}, a2 = {
	0x100, "Msg from 0x100-2"
}, b = {
	0x200, "Msg from 0x200"
};

int main() {
	RHTable *htable = NULL;
	struct test_value *geta, *getb;
	htable = r_htable_new (64);
	r_htable_add_uint64 (htable, 0x100, &a);
	// r_htable_add_uint64 (htable, 0x100, &a2);
	r_htable_add_uint64 (htable, 0x200, &b);
	geta = r_htable_get_uint64 (htable, 0x100);
	getb = r_htable_get_uint64 (htable, 0x200);
	printf ("result: 0x100=>%s, 0x200=>%s\n", geta->msg, getb->msg);
	r_htable_free (htable);
}

#endif
