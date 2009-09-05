#include <list.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct list_head head;

struct foo {
	char *name;
	struct list_head list;
};

struct list_head *get_list() {
	INIT_LIST_HEAD(&head);
	struct foo *a = malloc(sizeof(struct foo));
	a->name = strdup("hello");
	list_add(&a->list, &head);
	struct foo *b = malloc(sizeof(struct foo));
	b->name = strdup("world");
	list_add(&b->list, &head);
	return &head;
}

#if TEST
main() {
	struct list_head *list = get_list();
	struct list_head *pos;
	list_for_each_prev(pos, list) {
		struct foo *p = list_entry(pos, struct foo, list);
		printf("%s\n", p->name);
	}
}
#endif
