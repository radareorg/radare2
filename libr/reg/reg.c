/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_reg.h>
#include <r_util.h>
#include <list.h>

static const char *types[R_REG_TYPE_LAST+1] = {
	"gpr", "drx", "fpu", "mmx", "xmm", "flg", "seg", NULL
};

R_API const char *r_reg_get_type(int idx) {
	if (idx>=0 && idx<R_REG_TYPE_LAST)
		return types[idx];
	return NULL;
}

static void r_reg_item_free(RRegItem *item) {
	free (item->name);
	free (item->flags);
	free (item);
}

R_API int r_reg_get_name_idx(const char *type) {
	if (type)
	switch (*type | (type[1]<<8)) {
	case 'p'+('c'<<8): return R_REG_NAME_PC;
	case 's'+('r'<<8): return R_REG_NAME_SR;
	case 's'+('p'<<8): return R_REG_NAME_SP;
	case 'b'+('p'<<8): return R_REG_NAME_BP;
	case 'a'+('0'<<8): return R_REG_NAME_A0;
	case 'a'+('1'<<8): return R_REG_NAME_A1;
	case 'a'+('2'<<8): return R_REG_NAME_A2;
	case 'a'+('3'<<8): return R_REG_NAME_A3;
	}
	return -1;
}

R_API int r_reg_set_name(RReg *reg, int role, const char *name) {
	if (role>=0 && role<R_REG_NAME_LAST) {
		reg->name[role] = r_str_dup (reg->name[role], name);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API const char *r_reg_get_name(RReg *reg, int role) {
	if (reg && role>=0 && role<R_REG_NAME_LAST)
		return reg->name[role];
	return NULL;
}

R_API void r_reg_free_internal(RReg *reg) {
	int i;
	for (i=0; i<R_REG_TYPE_LAST; i++)
		r_list_destroy (reg->regset[i].regs);
}

R_API RReg *r_reg_free(RReg *reg) {
	if (reg) {
		int i;
		for (i=0; i<R_REG_TYPE_LAST; i++)
			r_list_destroy (reg->regset[i].pool);
		r_reg_free_internal (reg);
		free (reg);
	}
	return NULL;
}

R_API RReg *r_reg_new() {
	int i;
	RRegArena *arena;
	RReg *reg = R_NEW (RReg);
	reg->iters = 0;
	reg->profile = NULL;
	reg->reg_profile_str = NULL;
	for (i=0; i<R_REG_NAME_LAST; i++)
		reg->name[i] = NULL;
	for (i=0; i<R_REG_TYPE_LAST; i++) {
		arena = r_reg_arena_new (0);
		if (!arena) return NULL;
		reg->regset[i].arena = arena;
		R_LIST_NEW (reg->regset[i].pool, r_reg_arena_free);
		R_LIST_NEW (reg->regset[i].regs, r_reg_item_free);
		r_list_append (reg->regset[i].pool, reg->regset[i].arena);
	}
	return reg;
}

static RRegItem *r_reg_item_new() {
	RRegItem *item = R_NEW0 (RRegItem);
	return item;
}

R_API int r_reg_type_by_name(const char *str) {
	int i;
	for (i=0; types[i] && i<R_REG_TYPE_LAST; i++)
		if (!strcmp (types[i], str))
			return i;
	if (!strcmp (str, "all"))
		return R_REG_TYPE_ALL;
	eprintf ("Unknown register type: '%s'\n", str);
	return R_REG_TYPE_LAST;
}

/* TODO: make this parser better and cleaner */
static int r_reg_set_word(RRegItem *item, int idx, char *word) {
	int ret = R_TRUE;
	switch (idx) {
	case 0:
		item->type = r_reg_type_by_name (word);
		break;
	case 1:
		item->name = strdup (word);
		break;
	/* spaguetti ftw!!1 */
	case 2:
		if (*word=='.') // XXX; this is kinda ugly
			item->size = atoi (word+1);
		else item->size = atoi (word)*8;
		break;
	case 3:
		if (*word=='.') // XXX; this is kinda ugly
			item->offset = atoi (word+1);
		else item->offset = atoi (word)*8;
		break;
	case 4:
		if (*word=='.') // XXX; this is kinda ugly
			item->packed_size = atoi (word+1);
		else item->packed_size = atoi (word)*8;
		break;
	case 5:
		item->flags = strdup (word);
		break;
	default:
		eprintf ("register set fail (%s)\n", word);
		ret = R_FALSE;
	}
	return ret;
}

/* TODO: make this parser better and cleaner */
R_API int r_reg_set_profile_string(RReg *reg, const char *str) {
	RRegItem *item;
	int setname = -1;
	int ret = R_FALSE;
	int lastchar = 0;
	int chidx = 0;
	int word = 0;
	char buf[512];

	if (!str||!reg)
		return R_FALSE;
	// XXX double free // free (reg->reg_profile_str);
	reg->reg_profile_str = strdup (str);
	*buf = '\0';
	/* format file is: 'type name size offset packedsize' */
	r_reg_free_internal (reg);
	item = r_reg_item_new ();

	while (*str) {
		if (*str == '#') {
			/* skip until newline */
			while (*str && *str != '\n') str++;
			continue;
		}
		switch (*str) {
		case ' ':
		case '\t':
			/* UGLY PASTAFARIAN PARSING */
			if (word==0 && *buf=='=') {
				setname = r_reg_get_name_idx (buf+1);
				if (setname == -1)
					eprintf ("Invalid register type: '%s'\n", buf+1);
			} else
			if (lastchar != ' ' && lastchar != '\t')
				r_reg_set_word (item, word, buf);
			chidx = 0;
			word++;
			break;
		case '\n':
			if (setname != -1)
				r_reg_set_name (reg, setname, buf);
			else if (word>3) {
				r_reg_set_word (item, word, buf);
				if (item->name != NULL) {
					r_list_append (reg->regset[item->type].regs, item);
					item = r_reg_item_new ();
				}
			}
			chidx = word = 0;
			*buf = 0;
			setname = -1;
			break;
		default:
			if (chidx>128) {// WTF!!
				eprintf ("PARSE FAILED\n");
				return R_FALSE;
			}
			buf[chidx++] = *str;
			buf[chidx] = 0;
			break;
		}
		lastchar = *str;
		str++;
	}
	r_reg_item_free (item);
	r_reg_fit_arena (reg);

	return *str?ret:R_TRUE;
}

R_API int r_reg_set_profile(RReg *reg, const char *profile) {
	int ret = R_FALSE;
	const char *base;
	char *str, *file;
	/* TODO: append .regs extension to filename */
	if ((str = r_file_slurp (profile, NULL))==NULL) {
 		// XXX we must define this varname in r_lib.h /compiletime/
		base = r_sys_getenv ("LIBR_PLUGINS");
		if (base) {
			file = r_str_concat (strdup (base), profile);
			str = r_file_slurp (file, NULL);
			free (file);
		}
	}
	if (str) ret = r_reg_set_profile_string (reg, str);
	else eprintf ("r_reg_set_profile: Cannot find '%s'\n", profile);
	return ret;
}

R_API RRegItem *r_reg_get(RReg *reg, const char *name, int type) {
	RListIter *iter;
	RRegItem *r;
	int i, e;
	if (!reg || !name)
		return NULL;
	if (type == -1) {
		i = 0;
		e = R_REG_TYPE_LAST;
	} else {
		i = type;
		e = type+1;
	}

	for (; i<e; i++) {
		r_list_foreach (reg->regset[i].regs, iter, r) {
			if (!strcmp (r->name, name))
				return r;
		}
	}
	return NULL;
}

R_API RList *r_reg_get_list(RReg *reg, int type) {
	if (type<0 || type>R_REG_TYPE_LAST)
		return NULL;
	return reg->regset[type].regs;
}

R_API ut64 r_reg_cmp(RReg *reg, RRegItem *item) {
	int len = (item->size/8); // TODO: must use r_mem_bitcmp or so.. flags not correctly checked
	int off = BITS2BYTES (item->offset);
	RRegArena *src = r_list_head (reg->regset[item->type].pool)->data;
	RRegArena *dst = r_list_head (reg->regset[item->type].pool)->n->data;
	if (off+len>src->size) len = src->size-off;
	if (off+len>dst->size) len = src->size-off;
	if (len>0)
	if (memcmp (dst->bytes+off, src->bytes+off, len)) {
		ut64 ret;
		int ptr = !(reg->iters%2);
		r_reg_arena_set (reg, ptr, 0);
		ret = r_reg_get_value (reg, item);
		r_reg_arena_set (reg, !ptr, 0);
		return ret;
	}
	return 0LL;
}

