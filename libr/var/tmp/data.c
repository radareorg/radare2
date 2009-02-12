/*
 * Copyright (C) 2008
 *       pancake <youterm.com>
 *
 * radare is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * radare is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with radare; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "main.h"
#include "code.h"
#include "data.h"
#include "undo.h"
#include "flags.h"
#include "arch/csr/dis.h"
#include "arch/arm/disarm.h"
#include "arch/ppc/ppc_disasm.h"
#include "arch/m68k/m68k_disasm.h"
#include "arch/x86/udis86/types.h"
#include "arch/x86/udis86/extern.h"
#include "list.h"

struct reflines_t *reflines = NULL;

static struct list_head vartypes;

/* variables */
void data_comment_init(int new)
{
	INIT_LIST_HEAD(&(vartypes));
}

int data_var_type_add(const char *typename, int size, const char *fmt)
{
	struct var_type_t *d = (struct var_type_t *)
		malloc(sizeof(struct var_type_t));
	strncpy(d->name, typename, sizeof(d->name));
	strncpy(d->fmt, fmt, sizeof(d->fmt));
	d->size = size;
	list_add(&(d->list), &vartypes);
	
	return 0;
}

int data_var_type_del(const char *typename)
{
	struct list_head *pos;
	u64 ret = 0;

	if (*typename==' ')typename=typename+1;

	list_for_each(pos, &vartypes) {
		struct var_type_t *d = (struct var_type_t *)list_entry(pos, struct var_type_t, list);
		if (!strcmp(typename, d->name)) {
			list_del(&(d->list));
			return 1;
		}
	}
	
	return 0;
}

int data_var_type_list()
{
	struct list_head *pos;
	u64 ret = 0;

	list_for_each(pos, &vartypes) {
		struct var_type_t *d = (struct var_type_t *)list_entry(pos, struct var_type_t, list);
		cons_printf("%s %d %s\n", d->name, d->size, d->fmt);
	}
	return ret;
	
}

const char *data_var_type_get(const char *datatype)
{
	struct list_head *pos;
	u64 ret = 0;

	list_for_each(pos, &vartypes) {
		struct var_type_t *d = (struct var_type_t *)list_entry(pos, struct var_type_t, list);
		//eprintf("---(%s)(%s)\n", d->name, datatype);
		if (!strcmp(datatype, d->name))
			return d;
	}
	return NULL;
}

int data_var_help()
{
	cons_printf(
		"Usage: Cv [name] [size] [pm-format-string]\n"
		"  Cv int 4 d   ; define 'int' type\n"
		"  Cv- int      ; remove 'int' var type\n"
		"  Cv float 4 f\n");
	return 0;
}

int data_var_cmd(const char *str)
{
	int len;
	char *vstr;
	char *arg, *arg2;
	STRALLOC(vstr, str, len);

	if (*str==' ')str=str+1;
	switch(*str) {
	case '?':
		return data_var_help();
	case '\0':
		/* list var types */
		data_var_type_list();
		break;
	case '-':
		data_var_type_del(str+1);
		break;
	default:
		arg = strchr(str, ' ');
		if (arg==NULL)
			return data_var_help();
		*arg='\0'; arg=arg+1;
		arg2 = strchr(arg, ' ');
		if (arg2==NULL)
			return data_var_help();
		*arg2='\0'; arg2=arg2+1;
		data_var_type_add(str, atoi(arg), arg2);
		break;
	}
	
	return 0;
}
