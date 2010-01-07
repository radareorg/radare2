/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_reg.h>
#include <r_util.h>
#include <list.h>

/* lifecycle */
static void r_reg_free_internal(struct r_reg_t *reg) {
	struct list_head *pos, *n;
	struct r_reg_item_t *r;
	int i;

	for(i=0;i<R_REG_TYPE_LAST;i++) {
		list_for_each_safe(pos, n, &reg->regset[i].regs) {
			r = list_entry(pos, struct r_reg_item_t, list);
			list_del(&r->list);
			free(r);
		}
	}
}

R_API struct r_reg_t *r_reg_free(struct r_reg_t *reg)
{
	if (reg) {
		// TODO: free more things here
		free(reg);
	}
	return NULL;
}

R_API struct r_reg_t *r_reg_init(struct r_reg_t *reg)
{
	int i;
	if (reg) {
		reg->profile = NULL;
		for(i=0;i<R_REG_TYPE_LAST;i++) {
			INIT_LIST_HEAD(&reg->regset[i].arenas);
			INIT_LIST_HEAD(&reg->regset[i].regs);
			reg->regset[i].arena = MALLOC_STRUCT(struct r_reg_arena_t);
			reg->regset[i].arena->size = 0;
			reg->regset[i].arena->bytes = malloc(1);
			list_add_tail(&reg->regset[i].arena->list, &reg->regset[i].arenas);
		}
	}
	return reg;
}

R_API struct r_reg_t *r_reg_new()
{
	struct r_reg_t *r = MALLOC_STRUCT(struct r_reg_t);
	return r_reg_init(r);
}

static struct r_reg_item_t *r_reg_item_new() {
	struct r_reg_item_t *item = MALLOC_STRUCT(struct r_reg_item_t);
	memset(item, 0, sizeof(struct r_reg_item_t));
	return item;
}

R_API int r_reg_type_by_name(const char *str)
{
	int type = -1; //R_REG_TYPE_ALL;
	// XXX: do not spaguetti
	if	(!strcmp(str, "gpr")) type = R_REG_TYPE_GPR;
	else if (!strcmp(str, "drx")) type = R_REG_TYPE_DRX;
	else if (!strcmp(str, "mmx")) type = R_REG_TYPE_MMX;
	else if (!strcmp(str, "xmm")) type = R_REG_TYPE_XMM;
	else if (!strcmp(str, "fpu")) type = R_REG_TYPE_FPU;
	else if (!strcmp(str, "fpu")) type = R_REG_TYPE_FLG;
	else if (!strcmp(str, "seg")) type = R_REG_TYPE_SEG;
	else if (!strcmp(str, "flg")) type = R_REG_TYPE_FLG;
	else	printf("Unknown register type: '%s'\n", str);
	return type;
}

/* TODO: make this parser better and cleaner */
static int r_reg_set_word(struct r_reg_item_t *item, int idx, char *word) {
	int ret = R_TRUE;
	switch(idx) {
	case 0:
		item->type = r_reg_type_by_name(word);
		break;
	case 1:
		item->name = strdup(word);
		break;
	/* spaguetti ftw!!1 */
	case 2:
		if (*word=='.') // XXX; this is kinda ugly
			item->size = atoi(word+1);
		else item->size = atoi(word)*8;
		break;
	case 3:
		if (*word=='.') // XXX; this is kinda ugly
			item->offset = atoi(word+1);
		else item->offset = atoi(word)*8;
		break;
	case 4:
		if (*word=='.') // XXX; this is kinda ugly
			item->packed_size = atoi(word+1);
		else item->packed_size = atoi(word)*8;
		break;
	default:
		eprintf ("register set fail\n");
		ret = R_FALSE;
	}
	return ret;
}

/* TODO: make this parser better and cleaner */
R_API int r_reg_set_profile_string(struct r_reg_t *reg, const char *str)
{
	int ret = R_FALSE;
	int lastchar = 0;
	int word = 0;
	int chidx = 0;
	char buf[256];
	struct r_reg_item_t *item;

	if (!str)
		return R_FALSE;
	buf[0]=0;
	/* format file is: 'type name size offset packedsize' */
	r_reg_free_internal(reg);
	item = r_reg_item_new();

	while(*str) {
		if (*str == '#') {
			/* skip until newline */
			while(*str && *str != '\n') str++;
			continue;
		}
		switch(*str) {
		case ' ':
		case '\t':
			if (lastchar != ' ' && lastchar != '\t') {
				r_reg_set_word(item, word, buf);
//				printf("WORD %d (%s)\n", word, buf);
				chidx = 0;
				word++;
			}
			break;
		case '\n':
			// commit new
			//printf("WORD %d (%s)\n", word, buf);
			if (word>3) {
				r_reg_set_word(item, word, buf);
				// TODO: add check to ensure that all the fields are defined
				// before adding it into the list
				if (item->name != NULL) {
					list_add_tail(&item->list, &reg->regset[item->type].regs);
	//printf("ADD REG(%s) type=%d\n", item->name, item->type);
					item = r_reg_item_new();
	//				printf("-----------\n");
				}
			}
			chidx = word = 0;
			break;
		default:
			if (chidx > 128) // WTF!!
				return R_FALSE;
			buf[chidx++] = *str;
			buf[chidx] = 0;
			break;
		}
		lastchar = *str;
		str++;
	}
	free(item->name);
	free(item);
	r_reg_fit_arena(reg);
	
	/* do we reach the end ? */
	if (!*str) ret = R_TRUE;
	return ret;
}

R_API int r_reg_set_profile(struct r_reg_t *reg, const char *profile)
{
	int ret = R_FALSE;
	char *str, *file;
	const char *base;
	/* TODO: append .regs extension to filename */
	str = r_file_slurp(profile, NULL);
	if (str == NULL) {
 		// XXX we must define this varname in r_lib.h /compiletime/
		base = r_sys_getenv("LIBR_PLUGINS");
		if (base) {
			file = r_str_concat(strdup(base), profile);
			str = r_file_slurp(profile, NULL);
			free(file);
		}
	}
	if (str)
		ret = r_reg_set_profile_string(reg, str);
	return ret;
}

R_API struct r_reg_item_t *r_reg_get(struct r_reg_t *reg, const char *name, int type)
{
	struct list_head *pos;
	struct r_reg_item_t *r;
	int i, e;

	if (type == -1) {
		i = 0;
		e = R_REG_TYPE_LAST;
	} else {
		i = type;
		e = type+1;
	}

	for(;i<e;i++) {
		list_for_each(pos, &reg->regset[i].regs) {
			r = list_entry(pos, struct r_reg_item_t, list);
			if (!strcmp(r->name, name))
				return r;
		}
	}
	return NULL;
}

R_API struct list_head *r_reg_get_list(struct r_reg_t *reg, int type)
{
	if (type < 0 || type > R_REG_TYPE_LAST)
		return NULL;
	return &reg->regset[type].regs;
}

/* vala example */
/*
	Debug dbg = new Debug();
	dbg.reg = new Register();

	foreach (unowned var foo in dbg.reg.get_list(Register.Type.GPR)) {
		if (foo.size == 32)
		stdout.printf("Register %s: 0x%08llx\n",
			foo.name, foo.size, dbg.reg.get_value(foo));
	}
*/
