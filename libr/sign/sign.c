/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_sign.h>

int r_sign_init(struct r_sign_t *sig)
{
	sig->count = 0;
	INIT_LIST_HEAD(&(sig->items));
	return R_TRUE;
}

int r_sign_set(struct r_sign_item_t *sig, const char *key, const char *value)
{
	if (!strcmp(key, "name")) {
		strncpy(sig->name, value, sizeof(sig->name));
	} else
	if (!strcmp(key, "size")) {
		sig->size = atoi(value);
	} else
	if (!strcmp(key, "cksum")) {
		sscanf(value, "%lx", &sig->csum);
	} 
	return R_TRUE;
//	fprintf(stderr, "%s:%s\n", key, value);
}

int r_sign_option(struct r_sign_t *sig, const char *option)
{
	/* set options here */
	return R_TRUE;
}

/* returns a freshly new rsign */
struct r_sign_item_t *r_sign_add(struct r_sign_t *sig)
{
	struct r_sign_item_t *r;
	sig->count ++;
	r = (struct r_sign_item_t *)malloc(sizeof(struct r_sign_item_t));
	memset(r, '\0', sizeof(struct r_sign_item_t));
	list_add_tail(&(r->list), &(sig->items));
	return r;
}

int r_sign_load_file(struct r_sign_t *sig, const char *file)
{
	int n;
	FILE *fd;
	char buf[1024];
	char *ptr;
	struct r_sign_item_t *cursig = r_sign_add(sig);

	fd = fopen(file, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open signature file.\n");
		return 0;
	}
	n = 0;
	while(!feof(fd)) {
		buf[0]='\0';
		fgets(buf, 1023, fd);
		if (buf[0]=='-') {
			/* next item */
			cursig = r_sign_add(sig);
			continue;
		}
		ptr = strchr(buf, ':');
		if (ptr) {
			*ptr = '\0';
			ptr = ptr+1;
			ptr[strlen(ptr)-1]='\0';
			r_sign_set(cursig, buf, ptr+1);
		}
	}
	fclose(fd);
	return n;
}

int r_sign_info(struct r_sign_t *sig)
{
	printf("Loaded %d signatures\n", sig->count);
	return R_TRUE;
}

struct r_sign_t *r_sign_free(struct r_sign_t *sig)
{
	free (sig);
	struct list_head *pos, *n;
	list_for_each_safe(pos, n, &sig->items) {
		struct r_sign_item_t *i = list_entry(pos, struct r_sign_item_t, list);
		free(i->bytes);
		free(i);
	}
	return NULL;
}

int r_sign_check(struct r_sign_t *sig, const char *binfile)
{
	if (binfile==NULL) {
		fprintf(stderr, "No file specified\n");
		return 0;
	}
	fprintf(stderr, "Checking loaded signatures against '%s'\n", binfile);
	return R_TRUE;
}

int r_sign_generate(struct r_sign_t *sig, const char *file, FILE *fd)
{
	fprintf(stderr, "Generating signature file for '%s'\n" , file);
	return R_TRUE;
}
