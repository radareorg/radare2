/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_sign.h>

R_API RSign *r_sign_new() {
	return r_sign_init (R_NEW (RSign));
}

R_API RSign *r_sign_init(RSign *sig) {
	sig->count = 0;
	INIT_LIST_HEAD (&(sig->items));
	return sig;
}

R_API int r_sign_item_set(RSignItem *sig, const char *key, const char *value) {
	if (!strcmp (key, "name")) {
		strncpy (sig->name, value, sizeof(sig->name));
	} else
	if (!strcmp (key, "size")) {
		sig->size = atoi (value);
	} else
	if (!strcmp (key, "cksum")) {
		sscanf (value, "%x", &sig->csum);
	} 
	return R_TRUE;
//	eprintf("%s:%s\n", key, value);
}

R_API int r_sign_option(RSign *sig, const char *option) {
	/* set options here */
	return R_TRUE;
}

// r_sign_item_new
R_API RSignItem *r_sign_add(RSign *sig) {
	RSignItem *r;
	sig->count ++;
	r = (RSignItem *)malloc (sizeof (RSignItem));
	memset (r, '\0', sizeof (RSignItem));
	list_add_tail (&(r->list), &(sig->items));
	return r;
}

R_API int r_sign_load_file(RSign *sig, const char *file) {
	int n;
	FILE *fd;
	char *ptr, buf[1024];
	RSignItem *item = r_sign_add (sig);

	fd = fopen (file, "r");
	if (fd == NULL) {
		eprintf ("Cannot open signature file.\n");
		return 0;
	}
	n = 0;
	while (!feof (fd)) {
		buf[0]='\0';
		fgets (buf, 1023, fd);
		if (buf[0]=='-') {
			/* next item */
			item = r_sign_add (sig);
			continue;
		}
		ptr = strchr (buf, ':');
		if (ptr) {
			*ptr = '\0';
			ptr = ptr+1;
			ptr[strlen (ptr)-1]='\0';
			r_sign_item_set (item, buf, ptr+1);
		}
	}
	fclose (fd);
	return n;
}

R_API int r_sign_info(RSign *sig) {
	eprintf ("Loaded %d signatures\n", sig->count);
	return R_TRUE;
}

R_API RSign *r_sign_free(struct r_sign_t *sig) {
	struct list_head *pos, *n;
	list_for_each_safe (pos, n, &sig->items) {
		RSignItem *i = list_entry (pos, RSignItem, list);
		free (i->bytes);
		free (i);
	}
	free (sig);
	return NULL;
}

R_API int r_sign_check(struct r_sign_t *sig, const char *binfile) {
	if (binfile==NULL) {
		eprintf ("No file specified\n");
		return 0;
	}
	eprintf ("Checking loaded signatures against '%s'\n", binfile);
	return R_TRUE;
}

R_API int r_sign_generate(struct r_sign_t *sig, const char *file, FILE *fd) {
	eprintf ("Generating signature file for '%s'\n" , file);
	return R_TRUE;
}
