/* radare - LGPL - Copyright 2009-2012 - pancake */

#include "r_db.h"
#include "r_util.h"

struct r_db_table_t *r_db_table_new(const char *name, const char *fmt, const char *fields) {
	int i;
	int offset = 0;
	struct r_db_table_t *table = R_NEW (RDatabaseTable);
	table->args = strdup (fields);
	table->nelems = r_str_word_set0 (table->args);
	if (table->nelems != strlen (fmt)) {
		eprintf ("r_db_table_new: Invalid arguments\n");
		/* XXX: refactor */
		free (table->args);
		free (table);
		table = NULL;
	} else {
		table->fmt = strdup (fmt);
		table->name = strdup (name);
		table->offset = (int*)malloc (sizeof (int)*table->nelems);
		for (i=0; i<table->nelems; i++) {
			table->offset[i] = offset;
			offset += 4;
		}
	}
	return table;
}

/* Get offset of given named field inside the table */
int r_db_table_key(struct r_db_table_t *table, const char *name) {
	const char *word;
	int i;
	for(i=0;i<table->nelems;i++) {
		word = r_str_word_get0(table->args, i);
		if (!strcmp(name, word))
			break;
	}
	return table->offset[i];
}

/* Get offset of the N field in the table */
int r_db_table_key_i(struct r_db_table_t *table, int elem) {
	int key = -1;
	if (elem>=0 && table->nelems<elem)
		key = table->offset[elem];
	return key;
}

/* Get name of the N field in the table */
const char *r_db_table_field_i(struct r_db_table_t *table, int elem) {
	const char *name = NULL;
	if (elem>=0 && table->nelems<elem)
		name = r_str_word_get0 (table->args, elem);
	return name;
}

void *r_db_table_free(struct r_db_table_t *table) {
	free(table);
	return NULL;
}
