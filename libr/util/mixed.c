/*
 * mixed data type
 */

// we need to store information in this way:
// indexed by strings, ut32, ut64 .. r_hashtable
// iterate over them
// get subset 

#include <r_util.h>

#define RMIXED_MAXKEYS 256
typedef struct r_mixed_data_t {
	int size;
	union {
		RHashTable *ht;
		RHashTable64 *ht64;
	} hash;
} RMixedData;

typedef struct r_mixed_t {
	RList *list;
	RMixedData *keys[RMIXED_MAXKEYS];
} RMixed;

R_API RMixed *r_mixed_new () {
	RMixed *m = R_NEW (RMixed);
	if (!m) return NULL;
	memset (m->keys, 0, sizeof (m->keys));
	m->list = r_list_new ();
	return m;
}

R_API void r_mixed_free (RMixed *m) {
	int i;
	for (i=0; i<RMIXED_MAXKEYS; i++) {
		if (m->keys[i]) {
			switch (m->keys[i]->size) {
			case 1: case 2: case 4:
				r_hashtable_free (m->keys[i]->hash.ht);
				break;
			case 8: r_hashtable64_free (m->keys[i]->hash.ht64);
				break;
			}
			free (m->keys[i]);
			m->keys[i] = NULL;
		}
	}
	r_list_destroy (m->list);
	free (m);
}

R_API int r_mixed_key_check(RMixed *m, int key, int sz) {
	if (key>=0 && key<RMIXED_MAXKEYS) {
		if (sz==1 || sz==2 || sz==4 || sz==8)
			return R_TRUE;
	}
	return R_FALSE;
}

#define R_MIXED_KEY(m,x,y,z) r_mixed_key(m, r_offsetof(x,z), sizeof(y->z))
R_API int r_mixed_key(RMixed *m, int key, int size) {
	if (size>0 && r_mixed_key_check (m, key, size)) {
		if (m->keys[key]) {
			m->keys[key]->size = size;
		} else {
			m->keys[key] = R_NEW (RMixedData);
			m->keys[key]->size = size;
			switch (size) {
			case 1: case 2: case 4:
				m->keys[key]->hash.ht = r_hashtable_new ();
				return R_TRUE;
			case 8: m->keys[key]->hash.ht64 = r_hashtable64_new ();
				return R_TRUE;
			}
		}
	}
	return R_FALSE;
}

// static
R_API ut64 r_mixed_get_value(int key, int sz, const void *p) {
	switch (sz) {
	case 1: return (ut64) *((ut8*)((ut8*)p+key));
	case 2: return (ut64) *((ut16*)((ut8*)p+key));
	case 4: return (ut64) *((ut32*)((ut8*)p+key));
	case 8: return (ut64) *((ut32*)((ut8*)p+key));
	}
	return 0LL;
}

R_API RList *r_mixed_get (RMixed *m, int key, ut64 value) {
	if (key>=0 && key<RMIXED_MAXKEYS)
	if (m->keys[key])
	switch (m->keys[key]->size) {
	case 1: case 2: case 4:
		return r_hashtable_lookup (m->keys[key]->hash.ht, (ut32)value);
	case 8: return r_hashtable64_lookup (m->keys[key]->hash.ht64, value);
	}
	return NULL;
}

R_API void *r_mixed_get0 (RMixed *m, int key, ut64 value) {
	RList *list = r_mixed_get (m, key, value);
	if (list && !r_list_empty (list))
		return r_list_head (list)->data;
	return NULL;
}

R_API int r_mixed_add (RMixed *m, void *p) {
	RHashTable *ht;
	RHashTable64 *ht64;
	RList *list = NULL;
	ut64 value;
	int i, size, ret = R_FALSE;;
	r_list_append (m->list, p);
	for (i=0; i<RMIXED_MAXKEYS; i++) {
		if (!m->keys[i])
			continue;
		size = m->keys[i]->size;
		value = r_mixed_get_value (i, size, p);
		switch (size) {
		case 1: case 2: case 4:
			ht = m->keys[i]->hash.ht;
			list = r_hashtable_lookup (ht, (ut32)value);
			if (!list) {
				list = r_list_new ();
				r_hashtable_insert (ht, (ut32)value, list);
			}
			r_list_append (list, p);
			ret = R_TRUE;
			break;
		case 8:
			ht64 = m->keys[i]->hash.ht64;
			list = r_hashtable64_lookup (ht64, value);
			if (!list) {
				list = r_list_new ();
				r_hashtable64_insert (ht64, value, list);
			}
			r_list_append (list, p);
			ret = R_TRUE;
			break;
		}
	}
	return ret;
}

R_API int r_mixed_del (RMixed *m, void *p) {
	int i;
	r_list_delete_data (m->list, p);
	// TODO delete indexed hashtables
	for (i=0; i<RMIXED_MAXKEYS; i++) {
		if (!m->keys[i]) continue;
		// TODO: remove that key ptr from everywhere
	}
	return R_FALSE;
}

#if TEST
typedef struct {
	char *name;
	ut32 hashname;
	int length;
	ut64 offset;
} TestStruct;

TestStruct *test_struct_new(const char *name, int length, ut64 offset) {
	TestStruct *ts = R_NEW (TestStruct);
	ts->name = strdup (name);
	ts->hashname = r_str_hash (name);
	ts->length = length;
	ts->offset = offset;
	return ts;
}

void test_struct_free(TestStruct *ts) {
	free (ts->name);
	free (ts);
}

int main () {
	RList *list;
	RListIter *iter;
	TestStruct *ts;
	RMixed *mx = r_mixed_new ();
	R_MIXED_KEY (mx, TestStruct, ts, hashname);
	R_MIXED_KEY (mx, TestStruct, ts, offset);

	r_mixed_add (mx, test_struct_new ("food", 12, 0x839481222000));
	r_mixed_add (mx, test_struct_new ("food", 12, 0x839481222000));
	r_mixed_add (mx, test_struct_new ("baar", 12, 0x441242910));
	r_mixed_add (mx, test_struct_new ("cocktel", 12, 0x224944));
	r_mixed_add (mx, test_struct_new ("cocktel2", 16, 0x224944));
	r_mixed_add (mx, test_struct_new ("cocktel3", 17, 0x224944));

	ts = r_mixed_get0 (mx, r_offsetof (TestStruct, hashname), (ut64)r_str_hash ("food"));
	if (ts) {
		printf ("NAM: %s\n", ts->name);
		printf ("LEN: %d\n", ts->length);
		printf ("OFF: %llx\n", ts->offset);
	} else eprintf ("oops. cannot find 'food'\n");

	eprintf ("--\n");
	list = r_mixed_get (mx, r_offsetof (TestStruct, offset), 0x224944);
	r_list_foreach (list, iter, ts) {
		printf ("NAM: %s\n", ts->name);
		printf ("LEN: %d\n", ts->length);
		printf ("OFF: %llx\n", ts->offset);
	}

	r_mixed_free (mx);
}
#endif
