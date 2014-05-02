/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */


#include "r_db.h"
void test_pair ();
void test_db();

struct item_t {
	char city[10];
	int people;
	int id;
};

#define K_ID R_DB_INDEXOF(struct item_t, id)
#define K_CITY R_DB_INDEXOF(struct item_t, city)

int main(int argc, char **argv) {
	test_pair ();
	test_db ();
	return 0;
}

void test_pair () {
	char *s;
	RPair *p = r_pair_new ();
	r_pair_set_sync_dir (p, "sdb-db-test");

	r_pair_set (p, "root", "clown");
	r_pair_set (p, ".branch", "clown");
	r_pair_set (p, "user.name", "pancake");
	r_pair_set (p, "user.pass", "password");

	s = r_pair_get (p, "user.name");
	printf ("user.name=%s\n", s);

	{
	RPairItem *o;
	RListIter *iter;
	RList *list = r_pair_list (p, "user");
	printf ("DUMP:\n");
	r_list_foreach (list, iter, o) {
		printf ("   %s = %s\n", o->k, o->v);
	}
	r_list_purge (list);
	}
	r_pair_sync (p);
}

void test_db() {
	RDatabase *db = r_db_new ();
	void **siter;
	struct item_t *it, tmp;

	r_db_add_id (db, K_CITY, 10);
	r_db_add_id (db, (int)(K_ID), sizeof (int));

	it = (struct item_t *)malloc(sizeof(struct item_t));
	strcpy(it->city, "bcn");
	it->people = 1024;
	it->id = 33;
	r_db_add (db, it);
	r_db_add (db, it);
	//printf("(ORIG) %p\n", it);

	tmp.id = 33;
	siter = r_db_get (db, K_ID, (void *)&tmp);
	for(; siter && *siter; siter=r_db_get_next (siter)) {
		struct item_t *foo = (struct item_t *)r_db_get_cur (siter);
//	printf("(GET) %p\n", foo);
		printf ("city: %s, people: %d, id: %d\n",
			foo->city, foo->people, foo->id);
	}

	/* delete */
	r_db_delete(db, it);
	printf("--> delete 1 item\n");

	/* list */
	tmp.id = 33;
	siter = r_db_get(db, K_ID, (void *)&tmp);
	for(; siter && siter[0]; siter=r_db_get_next(siter)) {
		struct item_t *foo = (struct item_t *)r_db_get_cur(siter);
	//	printf("(GET) %p\n", foo);
		printf("city: %s, people: %d, id: %d\n",
			foo->city, foo->people, foo->id);
	}

#if 0
  |---| key
|--.--.--.--.--|
|--.--.--.--.--|
#endif
	printf("--> iterate over full list\n");
	{
		struct r_db_iter_t *iter;

		iter = r_db_iter_new(db, K_ID); // iter = db.iterator(K_ID);
		//while (r_db_iter_cur(iter)) {   // while(iter.exists()) {
		while (iter->cur) {   // while(iter.exists()) {
			struct item_t *foo = (struct item_t *)iter->cur; //r_db_iter_cur(siter);
			printf("city: %s, people: %d, id: %d\n",
				foo->city, foo->people, foo->id);
			r_db_iter_next(iter);
		}
	}

	printf("--> free db\n");
	r_db_free(db);
}
