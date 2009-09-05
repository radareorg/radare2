#include <list.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct list_head head;

typedef struct foo {
	char *name;
	struct list_head list;
} foo;

#define ralist_iterator(x) x->next
#define ralist_get(x) list_entry(x, struct foo, list); x=x->next
#define ralist_next(x) (x=x->next, (x != head))
#define ralist_free(x) (x)
#define foo_free(x) x
//void *ralist_free_(void *a) { return NULL; }
