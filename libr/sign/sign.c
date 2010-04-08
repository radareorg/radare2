/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_sign.h>

R_API RSign *r_sign_new() {
	return r_sign_init (R_NEW (RSign));
}

R_API RSign *r_sign_init(RSign *sig) {
	if (sig) {
		sig->s_byte = sig->s_anal = 0;
		sig->prefix[0] = '\0';
		sig->printf = (FunctionPrintf) printf;
		INIT_LIST_HEAD (&(sig->items));
	}
	return sig;
}

R_API void r_sign_prefix(RSign *sig, const char *str) {
	strncpy (sig->prefix, str, sizeof (sig->prefix));
	sig->prefix[sizeof (sig->prefix)] = '\0';
}

R_API int r_sign_add(RSign *sig, int type, const char *name, const char *arg) {
	int len, ret = R_FALSE;
	RSignItem *si; // TODO: like in r_search.. we need r_sign_item_new ()
			// TODO: but..we need to use a pool here..
	if (!name || !arg)
		return R_FALSE;

	switch (type) {
	case R_SIGN_BYTES:
		if (strstr (arg, ".."))
			eprintf ("head/tail signatures not yet supported\n");
		if (strstr (arg, ":"))
			eprintf ("binmasks not supported yet\n");

		si = R_NEW (RSignItem);
		if (si == NULL)
			break;
		si->type = type;
		snprintf (si->name, sizeof (si->name), "%s.%s",
			*sig->prefix?sig->prefix:"sign", name);
		len = strlen (arg);
		si->bytes = (ut8 *)malloc (len);
		si->mask = (ut8 *)malloc (len);
		if (si->bytes == NULL || si->mask == NULL) {
			eprintf ("Cannot malloc\n");
			free (si->mask);
			free (si->bytes);
			free (si);
			break;
		}
		si->size = r_hex_str2binmask (arg, si->bytes, si->mask);
		if (si->size<1) {
			free (si->bytes);
			free (si);
		} else list_add_tail (&(si->list), &(sig->items));
		sig->s_byte++;
		break;
	default:
	case R_SIGN_ANAL:
		eprintf ("r_sign_add: TODO\n");
		break;
	}
	return ret;
}

R_API void r_sign_list(RSign *sig, int rad) {
	if (rad) {
		struct list_head *pos;
		sig->printf ("zp-");
		list_for_each (pos, &sig->items) {
			RSignItem *si = list_entry (pos, RSignItem, list);
			sig->printf ("z%c %s ...\n", si->type, si->name); // TODO : show bytes
		}
	} else {
		sig->printf ("Loaded %d signatures\n", sig->s_byte + sig->s_anal);
		sig->printf ("  %d byte signatures\n", sig->s_byte);
		sig->printf ("  %d anal signatures\n", sig->s_anal);
	}
}

R_API void r_sign_reset(RSign *sig) {
	struct list_head *pos, *n;
	list_for_each_safe (pos, n, &sig->items) {
		RSignItem *i = list_entry (pos, RSignItem, list);
		free (i->bytes);
		free (i);
	}
	INIT_LIST_HEAD (&(sig->items));
}

R_API RSign *r_sign_free(RSign *sig) {
	r_sign_reset (sig);
	free (sig);
	return NULL;
}

R_API RSignItem *r_sign_check(RSign *sig, const ut8 *buf, int len) {
	struct list_head *pos;
	list_for_each (pos, &sig->items) {
		RSignItem *si = list_entry (pos, RSignItem, list);
		if (si->type == R_SIGN_BYTES) {
			int l = (len>si->size)?si->size:len;
			if (!r_mem_cmp_mask (buf, si->bytes, si->mask, l)) {
				return si;
			}
		}
	}
	return NULL;
}

/// DEPREACATE
R_API int r_sign_generate(RSign *sig, const char *file, FILE *fd) {
	eprintf ("Generating signature file for '%s'\n" , file);
	return R_TRUE;
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
