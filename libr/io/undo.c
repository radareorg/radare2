/*
 * Copyright (C) 2007, 2008, 2009
 *       pancake <@youterm.com>
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
#include "radare.h"
#include "list.h"
#include "undo.h"

#if 0
* Handle changes in write and seeks
* Per-fd history log
#endif

#if 0
/* History for writes support indexing and undo/redo with state flags */
static struct list_head undo_w_list;
static int undo_w_init = 0;
static int undo_w_lock = 0;

/* History for the N last seeks, stack-like access */
#define UNDOS 64
static u64 undos[UNDOS];
static int undos_idx = 0;
static int undos_lim = 0;
#endif


int r_io_undo_init(struct r_io_undo_t *undo)
{
	u->undo_w_init = 0;
	u->undo_w_lock = 0;
	u->undos_idx = 0;
	u->undos_lim = 0;
	return R_TRUE;
}

// u64 r_io_undo_get_last()
{
}

u64 undo_get_last_seek()
{
	if (undos_idx==0)
		return config.seek;
	return undos[undos_idx-2];
}

void undo_seek()
{
	if (--undos_idx<0)
		undos_idx = 0;
	else config.seek = undos[undos_idx-1];
}

void undo_redo()
{
	if (undos_idx<undos_lim) {
		undos_idx+=2;
		undo_seek();
	}
}

void undo_push()
{
	int i;

	if (undos[undos_idx-1] == config.seek)
		return;

	undos[undos_idx] = config.seek;
	if (undos_idx==UNDOS-1) {
		for(i=1;i<UNDOS;i++)
			undos[i-1] = undos[i];
	} else
		undos_idx++;

	if (undos_lim<undos_idx)
		undos_lim = undos_idx;
}

void undo_reset()
{
	undos_idx = 0;
}

void undo_list()
{
	int i;
	if (undos_idx<1)
		eprintf("-no seeks done-\n");
	else {
		cons_printf("f undo_idx @ %d\n", undos_idx);
		for(i=undos_idx-1;i!=0;i--)
			cons_printf("f undo_%d @ 0x%llx\n", undos_idx-1-i, undos[i-1]);
	}
}

void undo_write_new(u64 off, const u8 *data, int len)
{
	struct undow_t *uw = (struct undow_t *)malloc(sizeof(struct undow_t));

	if (!config_get_i("file.undowrite"))
		return;

	if (undo_w_lock)
		return;

	if (!undo_w_init) {
		undo_w_init = 1;
		INIT_LIST_HEAD(&(undo_w_list));
	}

	/* undo changes */
	uw->set = UNDO_WRITE_SET;
	uw->off = off;
	uw->len = len;
	uw->n = (u8*) malloc(len);
	memcpy(uw->n, data, len);
	uw->o = (u8*) malloc(len);
	radare_read_at(off, uw->o, len);
	list_add_tail(&(uw->list), &(undo_w_list));
}

void undo_write_clear()
{
	// XXX memory leak
	INIT_LIST_HEAD(&(undo_w_list));
}

int undo_write_size()
{
	struct list_head *p;
	int i = 0;

	if (undo_w_init)
	list_for_each_prev(p, &(undo_w_list)) {
		i++;
	}
	return i;
}

void undo_write_list()
{
#define BW 8 /* byte wrap */
	struct list_head *p;
	int i = 0, j, len;

	if (undo_w_init)
	list_for_each_prev(p, &(undo_w_list)) {
		struct undow_t *u = list_entry(p, struct undow_t, list);
		cons_printf("%02d %c %d %08llx: ", i, u->set?'+':'-', u->len, u->off);
		len = (u->len>BW)?BW:u->len;
		for(j=0;j<len;j++) cons_printf("%02x ", u->o[j]);
		if (len == BW) cons_printf(".. ");
		cons_printf ("=> ");
		for(j=0;j<len;j++) cons_printf("%02x ", u->n[j]);
		if (len == BW) cons_printf(".. ");
		cons_newline();
		i++;
	}
}

int undo_write_set_t(struct undow_t *u, int set) 
{
	undo_w_lock = 1;
	if (set) {
		radare_write_at(u->off, u->n, u->len);
		u->set = UNDO_WRITE_SET;
	} else {
		radare_write_at(u->off, u->o, u->len);
		u->set = UNDO_WRITE_UNSET;
	}
	undo_w_lock = 0;
	return 0;
}

void undo_write_set_all(int set)
{
	struct list_head *p;

	if (undo_w_init)
	list_for_each_prev(p, &(undo_w_list)) {
		struct undow_t *u = list_entry(p, struct undow_t, list);
		undo_write_set_t(u, set); //UNDO_WRITE_UNSET);
		eprintf("%s 0x%08llx\n", set?"redo":"undo", u->off);
	}
}

/* sets or unsets the writes done */
/* if ( set == 0 ) unset(n) */
int undo_write_set(int n, int set) 
{
	struct undow_t *u = NULL;
	struct list_head *p;
	int i = 0;

	if (undo_w_init) {
		list_for_each_prev(p, &(undo_w_list)) {
			if (i++ == n) {
				u = list_entry(p, struct undow_t, list);
				break;
			}
		}

		if (u) undo_write_set_t(u, set);
		else eprintf("invalid undo-write index\n");
	} else
		eprintf("no writes done\n");

	return 0;
}
