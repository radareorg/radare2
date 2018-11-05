/* radare - LGPL - Copyright 2007-2018 - pancake */

#include <r_flag.h>

#define ISNULLSTR(x) (!(x) || !*(x))

R_API RFlagItem *r_flag_item_new (void) {
	return R_NEW0 (RFlagItem);
}

R_API RFlagItem *r_flag_item_clone(RFlagItem *item) {
	r_return_val_if_fail (item, NULL);

	RFlagItem *n = R_NEW0 (RFlagItem);
	if (!n) {
		return NULL;
	}
	n->color = item->color ? strdup (item->color) : NULL;
	n->comment = item->comment ? strdup (item->comment) : NULL;
	n->alias = item->alias ? strdup (item->alias) : NULL;
	n->name = item->name ? strdup (item->name) : NULL;
	n->realname = item->realname ? strdup (item->realname) : NULL;
	n->offset = item->offset;
	n->size = item->size;
	n->space = item->space;
	return n;
}

R_API void r_flag_item_free(RFlagItem *item) {
	if (!item) {
		return;
	}
	free (item->color);
	free (item->comment);
	free (item->alias);
	/* release only one of the two pointers if they are the same */
	if (item->name != item->realname) {
		free (item->name);
	}
	free (item->realname);
	free (item);
}

/* add/replace/remove the alias of a flag item */
R_API void r_flag_item_set_alias(RFlagItem *item, const char *alias) {
	r_return_if_fail (item);
	free (item->alias);
	item->alias = ISNULLSTR (alias)? NULL: strdup (alias);
}

/* add/replace/remove the comment of a flag item */
R_API void r_flag_item_set_comment(RFlagItem *item, const char *comment) {
	r_return_if_fail (item);
	free (item->comment);
	item->comment = ISNULLSTR (comment) ? NULL : strdup (comment);
}

/* add/replace/remove the realname of a flag item */
R_API void r_flag_item_set_realname(RFlagItem *item, const char *realname) {
	r_return_if_fail (item);
	if (item->name != item->realname) {
		free (item->realname);
	}
	item->realname = ISNULLSTR (realname) ? NULL : strdup (realname);
}
