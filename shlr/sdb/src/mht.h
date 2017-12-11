
#define MHTSZ 32
#define MHTNO 0

typedef ut64 mhti;

typedef struct {
	mhti k;
	mhti v;
	void *u;
#if 0
	// unaligned
	// on 32bits
	void *pad;
	// on 64bits
	void *pad;
#endif
} mhtkv;

// 4 + 4 + 4 = 12 .. missing 4 more
// 8 + 8 + 4 = 20 .. missing 16, what about 32 ?
// 8 + 8 + 8 = 24 .. still not there, missing 8
// 4 + 4 + 8 = 16 .. lgtm

typedef void (*mht_freecb)(void *);

typedef struct {
	void **table; //[MHTSZ];
	mht_freecb f;
	ut32 size;
} mht;

typedef mht SdbMini;

mht *mht_new(ut32 size, mht_freecb f);
void mht_free(mht*);
void mht_init(mht *m, ut32, mht_freecb f);
void mht_fini(mht *m);
mhti mht_hash(const char *s);
bool mht_set(mht *m, mhti k, mhti v, void *u);
mhtkv *mht_getr(mht *m, mhti k);
mhtkv *mht_getr(mht *m, mhti k);
mhti mht_get(mht *m, mhti k);
mhti mht_get(mht *m, mhti k);
void *mht_getu(mht *m, mhti k);
bool mht_add(mht *m, mhti k, mhti v, void *u);
bool mht_del(mht *m, mhti k);
