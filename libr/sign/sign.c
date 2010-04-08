/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_sign.h>

R_API RSign *r_sign_new() {
	return r_sign_init (R_NEW (RSign));
}

R_API RSign *r_sign_init(RSign *sig) {
	sig->s_byte = sig->s_anal = 0;
	INIT_LIST_HEAD (&(sig->items));
	return sig;
}

R_API int r_sign_add(RSign *sig, int type, const char *name, const char *arg) {
	int ret = R_FALSE;
	switch (type) {
	case R_SIGN_BYTES:
		eprintf ("r_sign_add: TODO (%s)(%s)\n", name, arg);
		sig->s_byte++;
		break;
	default:
	case R_SIGN_GRAPH:
		eprintf ("r_sign_add: TODO\n");
		break;
	}
	return ret;
}

#if 0
// XXX This shit depends only on the graphing stuff.. will be remove when this part gets working
// XXX : remove.. deprecated stuff
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

// XXX: deprecate here.. must 
R_API int r_sign_option(RSign *sig, const char *option) {
	/* set options here */
	return R_TRUE;
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
#endif

#if 0
// r_sign_item_new
R_API RSignItem *r_sign_add(RSign *sig) {
	RSignItem *r;
	r = (RSignItem *)malloc (sizeof (RSignItem));
	memset (r, '\0', sizeof (RSignItem));
	list_add_tail (&(r->list), &(sig->items));
	return r;
}
#endif

R_API int r_sign_info(RSign *sig) {
	eprintf ("Loaded %d signatures\n", sig->s_byte + sig->s_anal);
	eprintf ("  %d byte signatures\n", sig->s_byte);
	eprintf ("  %d anal signatures\n", sig->s_anal);
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

/// DEPREACATE
R_API int r_sign_check(struct r_sign_t *sig, const char *binfile) {
	if (binfile==NULL) {
		eprintf ("No file specified\n");
		return 0;
	}
	eprintf ("Checking loaded signatures against '%s'\n", binfile);
	return R_TRUE;
}

/// DEPREACATE
R_API int r_sign_generate(struct r_sign_t *sig, const char *file, FILE *fd) {
	eprintf ("Generating signature file for '%s'\n" , file);
	return R_TRUE;
}
