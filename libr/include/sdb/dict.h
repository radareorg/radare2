
#define MHTSZ 32
#define MHTNO 0

typedef ut64 dicti;

typedef struct {
	dicti k;
	dicti v;
	void *u;
#if 0
	// unaligned
	// on 32bits
	void *pad;
	// on 64bits
	void *pad;
#endif
} dictkv;

// 4 + 4 + 4 = 12 .. missing 4 more
// 8 + 8 + 4 = 20 .. missing 16, what about 32 ?
// 8 + 8 + 8 = 24 .. still not there, missing 8
// 4 + 4 + 8 = 16 .. lgtm

typedef void (*dict_freecb)(void *);
typedef int (*dictkv_cb)(dictkv *, void *);

typedef struct {
	void **table; //[MHTSZ];
	dict_freecb f;
	ut32 size;
} dict;

typedef dict SdbMini;

SDB_API dict *dict_new(ut32 size, dict_freecb f);
SDB_API void dict_free(dict*);
SDB_API bool dict_init(dict *m, ut32, dict_freecb f);
SDB_API void dict_fini(dict *m);
SDB_API void dict_stats(dict *m);
SDB_API dicti dict_hash(const char *s);
SDB_API bool dict_set(dict *m, dicti k, dicti v, void *u);
SDB_API dictkv *dict_getr(dict *m, dicti k);
SDB_API dictkv *dict_getr(dict *m, dicti k);
SDB_API dicti dict_get(dict *m, dicti k);
SDB_API dicti dict_get(dict *m, dicti k);
SDB_API void *dict_getu(dict *m, dicti k);
SDB_API bool dict_add(dict *m, dicti k, dicti v, void *u);
SDB_API bool dict_del(dict *m, dicti k);
SDB_API void dict_foreach(dict *m, dictkv_cb cb, void *u);
