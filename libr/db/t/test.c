#include "r_db.h"

struct item_t {
	char city[10];
	int people;
	int id;
};

#define K_ID R_DB_INDEXOF(struct item_t, id)

int main(int argc, char **argv)
{
	struct r_db_t *db = r_db_new();
	struct item_t *it, tmp;
	r_db_add_id(db, R_DB_INDEXOF(struct item_t, city), 10);
	r_db_add_id(db, R_DB_INDEXOF(struct item_t, id), sizeof(int));
	it = (struct item_t *)malloc(sizeof(struct item_t));
	strcpy(it->city, "bcn");
	it->people = 1024;
	it->id = 33;
	r_db_add(db, it);

	tmp.id=33;
	it = (struct item_t *)r_db_get(db, K_ID, (void *)&tmp);
	for(;it;it=r_db_get_next(it)) {
		printf("%s, %d, %d\n", it->city, it->people, it->id);
	}
	r_db_free(db);
}
