/* radare - LGPL - Copyright 2019 - pancake, ret2libc */

#include "r_util/r_spaces.h"

R_API RSpaces *r_spaces_new(const char *name) {
	RSpaces *sp = R_NEW0 (RSpaces);
	if (!sp || !r_spaces_init (sp, name)) {
		free (sp);
		return NULL;
	}
	return sp;
}

R_API bool r_spaces_init(RSpaces *sp, const char *name) {
	r_return_val_if_fail (sp && name, false);
	sp->name = strdup (name);
	if (!sp->name) {
		goto fail;
	}

	sp->spaces = NULL;
	sp->current = NULL;
	sp->spacestack = r_list_new ();
	if (!sp->spacestack) {
		goto fail;
	}

	sp->event = r_event_new (sp);
	if (!sp->event) {
		goto fail;
	}

	return true;

fail:
	r_spaces_fini (sp);
	return false;
}

R_API void r_spaces_free(RSpaces *sp) {
	r_spaces_fini (sp);
	free (sp);
}

static void space_free(RSpace *s) {
	if (s) {
		free (s->name);
		free (s);
	}
}

static void space_node_free(RBNode *n, void *user) {
	RSpace *s = container_of (n, RSpace, rb);
	space_free (s);
}

R_API void r_spaces_fini(RSpaces *sp) {
	r_list_free (sp->spacestack);
	sp->spacestack = NULL;
	r_rbtree_free (sp->spaces, space_node_free, NULL);
	sp->spaces = NULL;
	r_event_free (sp->event);
	sp->event = NULL;
	sp->current = NULL;
	R_FREE (sp->name);
}

R_API void r_spaces_purge(RSpaces *sp) {
	sp->current = NULL;
	r_list_purge (sp->spacestack);
	r_rbtree_free (sp->spaces, space_node_free, NULL);
	sp->spaces = NULL;
}

static int name_space_cmp(const void *incoming, const RBNode *rb, void *user) {
	const RSpace *s = container_of (rb, const RSpace, rb);
	return strcmp (incoming, s->name);
}

R_API RSpace *r_spaces_get(RSpaces *sp, const char *name) {
	if (!name) {
		return NULL;
	}
	RBNode *n = r_rbtree_find (sp->spaces, (void *)name, name_space_cmp, NULL);
	return n? container_of (n, RSpace, rb): NULL;
}

static int space_cmp(const void *incoming, const RBNode *rb, void *user) {
	const RSpace *a = (const RSpace *)incoming;
	const RSpace *b = container_of (rb, const RSpace, rb);
	return strcmp (a->name, b->name);
}

R_API RSpace *r_spaces_add(RSpaces *sp, const char *name) {
	r_return_val_if_fail (sp, NULL);
	if (!name || !*name || *name == '*') {
		return NULL;
	}

	RSpace *s = r_spaces_get (sp, name);
	if (s) {
		return s;
	}

	s = R_NEW0 (RSpace);
	if (!s) {
		return NULL;
	}

	s->name = strdup (name);
	if (!s->name) {
		free (s);
		return NULL;
	}

	r_rbtree_insert (&sp->spaces, s, &s->rb, space_cmp, NULL);
	return s;
}

R_API RSpace *r_spaces_set(RSpaces *sp, const char *name) {
	sp->current = r_spaces_add (sp, name);
	return sp->current;
}

static bool spaces_unset_single(RSpaces *sp, const char *name) {
	RSpace *space = r_spaces_get (sp, name);
	if (!space) {
		return false;
	}

	RSpaceEvent ev = { .data.unset.space = space };
	r_event_send (sp->event, R_SPACE_EVENT_UNSET, &ev);
	if (sp->current == space) {
		sp->current = NULL;
	}
	return r_rbtree_delete (&sp->spaces, (void *)name, name_space_cmp, NULL, space_node_free, NULL);
}

R_API bool r_spaces_unset(RSpaces *sp, const char *name) {
	if (name) {
		return spaces_unset_single (sp, name);
	}

	RList *names = r_list_newf ((RListFree)free);
	if (!names) {
		return false;
	}

	RBIter it;
	RSpace *s;
	r_spaces_foreach (sp, it, s) {
		r_list_append (names, strdup (s->name));
	}

	RListIter *lit;
	const char *n;
	bool res = false;
	r_list_foreach (names, lit, n) {
		res |= spaces_unset_single (sp, n);
	}
	r_list_free (names);
	return res;
}

R_API int r_spaces_count(RSpaces *sp, const char *name) {
	RSpace *s = r_spaces_get (sp, name);
	if (!s) {
		return 0;
	}
	RSpaceEvent ev = { .data.count.space = s, .res = 0 };
	r_event_send (sp->event, R_SPACE_EVENT_COUNT, &ev);
	return ev.res;
}

R_API bool r_spaces_push(RSpaces *sp, const char *name) {
	r_return_val_if_fail (sp, false);

	r_list_push (sp->spacestack, sp->current? sp->current->name: "*");
	r_spaces_set (sp, name);
	return true;
}

R_API bool r_spaces_pop(RSpaces *sp) {
	char *name = r_list_pop (sp->spacestack);
	if (!name) {
		return false;
	}

	RSpace *s = r_spaces_get (sp, name);
	r_spaces_set (sp, s? s->name: NULL);
	return true;
}

R_API bool r_spaces_rename(RSpaces *sp, const char *oname, const char *nname) {
	if (!oname && !sp->current) {
		return false;
	}

	RSpace *s;
	if (oname) {
		s = r_spaces_get (sp, oname);
		if (!s) {
			return false;
		}
	} else {
		s = sp->current;
	}

	RSpace *sn = r_spaces_get (sp, nname);
	if (sn) {
		return false;
	}

	RSpaceEvent ev = {
		.data.rename.oldname = s->name,
		.data.rename.newname = nname,
		.data.rename.space = s
	};
	r_event_send (sp->event, R_SPACE_EVENT_RENAME, &ev);

	r_rbtree_delete (&sp->spaces, (void *)s->name, name_space_cmp, NULL, NULL, NULL);
	free (s->name);
	s->name = strdup (nname);
	r_rbtree_insert (&sp->spaces, s, &s->rb, space_cmp, NULL);

	return true;
}
