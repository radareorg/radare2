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
static struct list_head data;
static struct list_head comments;
static struct list_head xrefs;

int data_set_len(u64 off, u64 len)
{
	struct list_head *pos;
	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (off>= d->from && off<= d->to) {
			d->to = d->from+len;
			d->size = d->to-d->from+1;
			return 0;
		}
	}
	return -1;
}

u64 data_prev(u64 off, int type)
{
	struct list_head *pos;
	u64 ret = 0;

	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (d->type == type) {
			if (d->from < off && d->to > off)
				ret = d->from;
		}
	}
	return ret;
}

int data_get_fun_for(u64 addr, u64 *from, u64 *to)
{
	struct list_head *pos;
	int n_functions = 0;
	int n_xrefs = 0;
	int n_dxrefs = 0;
	struct data_t *rd = NULL;
	u64 lastfrom = 0LL;

	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (d->type == DATA_FUN) {
			if (d->from < addr && d->from > lastfrom) {
				rd = d;
			}
		}
	}
	if (rd) {
		*from = rd->from;
		*to = rd->to;
		return 1;
	}
	return 0;
}

void data_info()
{
	struct list_head *pos;
	int n_functions = 0;
	int n_xrefs = 0;
	int n_dxrefs = 0;

	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (d->type == DATA_FUN)
			n_functions++;
	}

	list_for_each(pos, &xrefs) {
		struct xrefs_t *x = (struct xrefs_t *)list_entry(pos, struct xrefs_t, list);
		if (x->type == 0)
			n_dxrefs++;
		else n_xrefs++;
	}
	
	cons_printf("functions: %d\n", n_functions);
	cons_printf("data_xrefs: %d\n", n_dxrefs);
	cons_printf("code_xrefs: %d\n", n_xrefs);
}

int data_set(u64 off, int type)
{
	struct list_head *pos;
	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (off>= d->from && off<= d->to) {
			d->type = type;
			return 0;
		}
	}
	return -1;
}

struct data_t *data_add_arg(u64 off, int type, const char *arg)
{
	struct data_t *d;
	if (arg == NULL)
		return NULL;
	d = data_add(off, type);
	if (d != NULL)
		strncpy(d->arg , arg, sizeof(d->arg));
	return d;
}

void data_del(u64 addr, int type,int len/* data or code */)
{
	struct data_t *d;
	struct list_head *pos;
	list_for_each(pos, &data) {
		d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (d->from == addr && type == d->type && (len==0||len==d->size)) {
			list_del(&(d->list));
			break;
		}
	}
}

struct data_t *data_add(u64 off, int type)
{
	u64 tmp;
	struct data_t *d = NULL;
	struct list_head *pos;

	__reloop:
	// TODO: use safe foreach here
	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (d && (off>= d->from && off< d->to) ) {
			list_del((&d->list));
			goto __reloop;
		}
	}

	if (type == DATA_CODE)
		return d;

	d = (struct data_t *)malloc(sizeof(struct data_t));
	memset(d, '\0', sizeof(d));
	d->arg[0]='\0';
	d->from = off;
	d->to = d->from + config.block_size;  // 1 byte if no cursor // on strings should autodetect

	if (config.cursor_mode) {
		d->to = d->from + 1;
		d->from+=config.cursor;
		if (config.ocursor!=-1)
			d->to = config.seek+config.ocursor;
		if (d->to < d->from) {
			tmp = d->to;
			d->to  = d->from;
			d->from = tmp;
		}
	}
	d->type = type;
	if (d->to > d->from) {
	//	d->to++;
		d->size = d->to - d->from+1;
	} else d->size = d->from - d->to+1;
	if (d->size<1)
		d->size = 1;

	list_add(&(d->list), &data);

	return d;
}

u64 data_seek_to(u64 offset, int type, int idx)
{
	u64 ret = 0ULL;
	struct list_head *pos;
	int i = 0;
	idx--;

	list_for_each(pos, &xrefs) {
		struct xrefs_t *d = (struct xrefs_t *)list_entry(pos, struct xrefs_t , list);
		if (d->type == type || type == -1) {
			if (d->addr == offset && idx == i) {
				ret = d->from;
				break;
			}
			i++;
		}
	}
	return ret;
}

struct data_t *data_get(u64 offset)
{
	struct list_head *pos;
	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (offset >= d->from && offset < d->to)
			return d;
	}
	return NULL;
}

struct data_t *data_get_range(u64 offset)
{
	struct list_head *pos;
	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (offset >= d->from && offset < d->to)
			return d;
	}
	return NULL;
}

/* TODO: OPTIMIZE: perform cache here */
struct data_t *data_get_between(u64 from, u64 to)
{
	int hex = 0;
	int str = 0;
	int fun = 0;
	int stc = 0;
	int code = 0;
	struct list_head *pos;
	struct data_t *d = NULL;
	static struct data_t ret;

	list_for_each(pos, &data) {
		d = (struct data_t *)list_entry(pos, struct data_t, list);
		//if (from >= d->from && to <= d->to) {
		if (d->from >= from && d->to < to) {
			switch(d->type) {
			case DATA_HEX: hex++; break;
			case DATA_STR: str++; break;
			case DATA_CODE: code++; break;
			case DATA_FUN: fun++; break;
			case DATA_STRUCT: stc++; break;
			}
		}
	}

#if 0
	if (d == NULL)
		return NULL;

	if (hex>=str && hex>=code && hex>=fun && hex >= stc) {
		d->type = DATA_HEX;
		d->times = hex;
	} else
	if (str>=hex && str>=code && str>=fun && str >= stc) {
		d->type = DATA_STR;
		d->times = str;
	} else
	if (fun>=hex && fun>=str && fun>=code && fun >= stc) {
		d->type = DATA_FUN;
		d->times = fun;
	} else
	if (code>=hex && code>=str && code>=fun && code >=stc) {
		d->type = DATA_CODE;
		d->times = code;
	} else
	if (stc>=hex && stc>=str && stc>=fun && stc>=code) {
		d->type = DATA_STRUCT;
		d->times = stc;
	}
	// TODO add struct
//printf("0x%llx-0x%llx: %d %d %d = %d\n", from, to, hex, str, code, d->type);

	return d;
#endif
	
	if (hex>=str && hex>=code && hex>=fun && hex >= stc) {
		ret.type = DATA_HEX;
		ret.times = hex;
	} else
	if (str>=hex && str>=code && str>=fun && str >= stc) {
		ret.type = DATA_STR;
		ret.times = str;
	} else
	if (fun>=hex && fun>=str && fun>=code && fun >= stc) {
		ret.type = DATA_FUN;
		ret.times = fun;
	} else
	if (code>=hex && code>=str && code>=fun && code >=stc) {
		ret.type = DATA_CODE;
		ret.times = code;
	} else
	if (stc>=hex && stc>=str && stc>=fun && stc>=code) {
		ret.type = DATA_STRUCT;
		ret.times = stc;
	}

	return &ret;
}

int data_type_range(u64 offset)
{
	struct data_t *d = data_get_range(offset);
	if (d != NULL)
		return d->type;
	return -1;
}

int data_type(u64 offset)
{
	struct list_head *pos;
	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (offset == d->from)
			return d->type;
	}
	return -1;
}

int data_end(u64 offset)
{
	struct list_head *pos;
	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (offset == d->from+d->size) // XXX: must be d->to..but is buggy ?
			return d->type;
	}
	return -1;
}

int data_size(u64 offset)
{
	struct list_head *pos;
	list_for_each(pos, &data) {
		struct data_t *d = (struct data_t *)list_entry(pos, struct data_t, list);
		if (offset == d->from)
			return d->size;
	}
	return 0;
}

// TODO: add grep flags here
int data_list_ranges()
{
	struct data_t *d;
	struct list_head *pos;

	list_for_each(pos, &data) {
		d = (struct data_t *)list_entry(pos, struct data_t, list);
		switch(d->type) {
		case DATA_FUN:
			cons_printf("ar+ 0x%08llx 0x%08llx\n",
				d->from, d->to);
			break;
		}
	}
}

/* TODO: add grep flags argument */
int data_list()
{
	char *arg;
	char label[1024];
	struct data_t *d;
	struct list_head *pos;

	list_for_each(pos, &data) {
		d = (struct data_t *)list_entry(pos, struct data_t, list);
		label[0]='\0';
		string_flag_offset(label, d->from, 0);
		arg = NULL;
		switch(d->type) {
		case DATA_FOLD_O: cons_strcat("Cu "); break;
		case DATA_FOLD_C: cons_strcat("Cf "); break;
		case DATA_FUN:    cons_strcat("CF "); break;
		case DATA_HEX:    cons_strcat("Cd "); break;
		case DATA_STR:    cons_strcat("Cs "); break;
		case DATA_STRUCT: cons_strcat("Cm "); arg = d->arg; break;
		default:          cons_strcat("Cc "); break; }
		cons_printf("%lld %s@ 0x%08llx ; %s", d->to-d->from, arg?arg:"", d->from, label);
#if 0
		if (verbose)
		if (d->type == DATA_STR) {
			cons_printf("  (");
			sprintf(label, "pz@0x%08llx", d->from);
			radare_cmd(label, 0);
		}else
#endif
		cons_newline();
	}
	return 0;
}
/* -- metadata -- */
int data_xrefs_print(u64 addr, int type)
{
	char str[1024];
	int n = 0;
	struct xrefs_t *x;
	struct list_head *pos;
	list_for_each(pos, &xrefs) {
		x = (struct xrefs_t *)list_entry(pos, struct xrefs_t, list);
		if (x->addr == addr) {
			str[0]='\0';
			string_flag_offset(str, x->from, 0);
			switch(type) {
			case 0: if (x->type == type) { cons_printf("; 0x%08llx CODE xref 0x%08llx (%s)\n", addr, x->from, str); n++; } break;
			case 1: if (x->type == type) { cons_printf("; 0x%08llx DATA xref 0x%08llx (%s)\n", addr, x->from), str; n++; } break;
			default: { cons_printf("; 0x%08llx %s xref from 0x%08llx (%s)\n", addr, (x->type==1)?"DATA":(x->type==0)?"CODE":"UNKNOWN",x->from, str); n++; };
			}
		}
	}

	return n;
}

int data_xrefs_add(u64 addr, u64 from, int type)
{
	struct xrefs_t *x;
	struct list_head *pos;

	/* avoid dup */
	list_for_each(pos, &xrefs) {
		x = (struct xrefs_t *)list_entry(pos, struct xrefs_t, list);
		if (x->addr == addr && x->from == from)
			return 0;
	}

	x = (struct xrefs_t *)malloc(sizeof(struct xrefs_t));

	x->addr = addr;
	x->from = from;
	x->type = type;

	list_add(&(x->list), &xrefs);

	return 1;
}

int data_xrefs_at(u64 addr)
{
	int ctr = 0;
	struct xrefs_t *x;
	struct list_head *pos;

	/* avoid dup */
	list_for_each(pos, &xrefs) {
		x = (struct xrefs_t *)list_entry(pos, struct xrefs_t, list);
		if (x->addr == addr)
			ctr++;
	}
	return ctr;

}

void data_xrefs_del(u64 addr, u64 from, int data /* data or code */)
{
	struct xrefs_t *x;
	struct list_head *pos;
	list_for_each(pos, &xrefs) {
		x = (struct xrefs_t *)list_entry(pos, struct xrefs_t, list);
		if (x->addr == addr && x->from == from) {
			list_del(&(x->list));
			break;
		}
	}
}

void data_comment_del(u64 offset, const char *str)
{
	struct comment_t *cmt;
	struct list_head *pos;
	//u64 off = get_math(str);

	list_for_each(pos, &comments) {
		cmt = list_entry(pos, struct comment_t, list);
#if 0
		if (!pos)
			return;
#endif

#if 0
		if (off) {
			if ((off == cmt->offset)) {
				free(cmt->comment);
				list_del(&(pos));
				free(cmt);
				if (str[0]=='*')
					data_comment_del(offset, str);
				pos = comments.next; // list_init
				return;
			}
		} else {
#endif
		    if (offset == cmt->offset) {
			    if (str[0]=='*') {
				    free(cmt->comment);
				    list_del(&(pos));
				    free(cmt);
				    pos = comments.next; // list_init
				    //data_comment_del(offset, str);
			    } else
			    if (!strcmp(cmt->comment, str)) {
				    list_del(&(pos));
				    return;
			    }
		    }
#if 0
		}
#endif
	}
}

void data_comment_add(u64 offset, const char *str)
{
	struct comment_t *cmt;
	char *ptr;

	/* no null comments */
	if (strnull(str))
		return;

	/* avoid dupped comments */
	data_comment_del(offset, str);

	cmt = (struct comment_t *) malloc(sizeof(struct comment_t));
	cmt->offset = offset;
	ptr = strdup(str);
	if (ptr[strlen(ptr)-1]=='\n')
		ptr[strlen(ptr)-1]='\0';
	cmt->comment = ptr;
	list_add_tail(&(cmt->list), &(comments));
}

void data_comment_list()
{
	struct list_head *pos;
	list_for_each(pos, &comments) {
		struct comment_t *cmt = list_entry(pos, struct comment_t, list);
		cons_printf("CC %s @ 0x%llx\n", cmt->comment, cmt->offset);
	}
}

void data_xrefs_here(u64 addr)
{
	int count = 0;
	char label[1024];
	struct xrefs_t *x;
	struct list_head *pos;

	list_for_each(pos, &xrefs) {
		x = (struct xrefs_t *)list_entry(pos, struct xrefs_t, list);
		if (addr = x->addr) {
			label[0]='\0';
			string_flag_offset(label, x->from, 0);
			cons_printf("%d %s xref 0x%08llx @ 0x%08llx ; %s\n",
				count+1, x->type?"data":"code", x->from, x->addr, label);
			count++;
		}
	}
	if (count == 0) {
		eprintf("No xrefs found\n");
	}
}

void data_xrefs_list()
{
	char label[1024];
	struct xrefs_t *x;
	struct list_head *pos;

	list_for_each(pos, &xrefs) {
		x = (struct xrefs_t *)list_entry(pos, struct xrefs_t, list);
		label[0]='\0';
		string_flag_offset(label, x->from, 0);
		cons_printf("C%c 0x%08llx @ 0x%08llx ; %s\n", x->type?'d':'x', x->from, x->addr, label);
	}
}

char *data_comment_get(u64 offset, int lines)
{
	struct list_head *pos;
	char *str = NULL;
	int cmtmargin = (int)config_get_i("asm.cmtmargin");
	int cmtlines = config_get_i("asm.cmtlines");
	char null[128];

	memset(null,' ',126);
	null[126]='\0';
	if (cmtmargin<0) cmtmargin=0; else
		// TODO: use screen width here
		if (cmtmargin>80) cmtmargin=80;
	null[cmtmargin] = '\0';
	if (cmtlines<0)
		cmtlines=0;

	if (cmtlines) {
		int i = 0;
		list_for_each(pos, &comments) {
			struct comment_t *cmt = list_entry(pos, struct comment_t, list);
			if (cmt->offset == offset)
				i++;
		}
		if (i>cmtlines)
			cmtlines = i-cmtlines;
	}

	list_for_each(pos, &comments) {
		struct comment_t *cmt = list_entry(pos, struct comment_t, list);
		if (cmt->offset == offset) {
			if (cmtlines) {
				cmtlines--;
				continue; // skip comment lines
			}
			if (str == NULL) {
				str = malloc(1024);
				str[0]='\0';
			} else {
				str = realloc(str, cmtmargin+strlen(str)+strlen(cmt->comment)+128);
			}
			strcat(str, null);
			strcat(str, "; ");
			strcat(str, cmt->comment);
			strcat(str, "\n");
			if (--lines == 0)
				break;
		}
	}
	return str;
}

void data_comment_init(int new)
{
	INIT_LIST_HEAD(&(vartypes));
	INIT_LIST_HEAD(&(xrefs));
	INIT_LIST_HEAD(&(comments));
	INIT_LIST_HEAD(&(data));
	var_init();
}

void data_reflines_init()
{
	int show_lines    = (int) config_get_i("asm.lines");
	reflines = NULL;
	if (show_lines)
		reflines = code_lines_init();
}

int data_printd(int delta)
{
	int show_lines = (int)config_get("asm.lines");
	u64 offset = (u64)config.seek + (u64)delta;// - config.vaddr;
	int lines = 0;
	const char *ptr;

	D {} else return 0;

	ptr = data_comment_get(offset, config.height-cons_lines);
	if (ptr && ptr[0]) {
		int i;
		for(i=0;ptr[i];i++)
			if (ptr[i]=='\n') lines++;
		C 	cons_printf(C_MAGENTA"%s"C_RESET, ptr);
		else 	cons_strcat(ptr);
		free((void *)ptr);
	}

	lines += data_xrefs_print(offset, -1);
	return lines;
}
