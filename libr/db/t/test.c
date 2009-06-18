/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_db.h"

struct item_t {
	char city[10];
	int people;
	int id;
};

#define K_ID R_DB_INDEXOF(struct item_t, id)
#define K_CITY R_DB_INDEXOF(struct item_t, city)

int main(int argc, char **argv)
{
	struct r_db_t *db = r_db_new();
	void **siter;
	struct item_t *it, tmp;

	r_db_add_id(db, K_CITY, 10);
	r_db_add_id(db, K_ID, sizeof(int));

	it = (struct item_t *)malloc(sizeof(struct item_t));
	strcpy(it->city, "bcn");
	it->people = 1024;
	it->id = 33;
	r_db_add(db, it);
	r_db_add(db, it);
	//printf("(ORIG) %p\n", it);

	tmp.id = 33;
	siter = r_db_get(db, K_ID, (void *)&tmp);
	for(; siter && siter[0]; siter=r_db_get_next(siter)) {
		struct item_t *foo = (struct item_t *)r_db_get_cur(siter);
	//	printf("(GET) %p\n", foo);
		printf("city: %s, people: %d, id: %d\n",
			foo->city, foo->people, foo->id);
	}

	/* delete */
	r_db_delete(db, it);

	/* list */
	tmp.id = 33;
	siter = r_db_get(db, K_ID, (void *)&tmp);
	for(; siter && siter[0]; siter=r_db_get_next(siter)) {
		struct item_t *foo = (struct item_t *)r_db_get_cur(siter);
	//	printf("(GET) %p\n", foo);
		printf("city: %s, people: %d, id: %d\n",
			foo->city, foo->people, foo->id);
	}
	r_db_free(db);

	return 0;
}
