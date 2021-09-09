/* radare - LGPL - Copyright 2010-2021 - pancake */

#include <r_debug.h>

R_API RDebugDesc *r_debug_desc_new(int fd, const char* path, int perm, int type, int off) {
	RDebugDesc *desc = R_NEW (RDebugDesc);
	if (desc) {
		desc->fd = fd;
		desc->path = strdup (path);
		desc->perm = perm;
		desc->type = type;
		desc->off = off;
	}
	return desc;
}

R_API void r_debug_desc_free(RDebugDesc *p) {
	if (p) {
		free (p->path);
		free (p);
	}
}

R_API int r_debug_desc_open(RDebug *dbg, const char *path) {
	r_return_val_if_fail (dbg && dbg->h, -1);
	if (dbg && dbg->h && dbg->h->desc.open) {
		return dbg->h->desc.open (path);
	}
	return -1;
}

R_API int r_debug_desc_close(RDebug *dbg, int fd) {
	if (dbg && dbg->h && dbg->h->desc.close) {
		return dbg->h->desc.close (fd);
	}
	return false;
}

R_API int r_debug_desc_dup(RDebug *dbg, int fd, int newfd) {
	if (dbg && dbg->h && dbg->h->desc.dup) {
		return dbg->h->desc.dup (fd, newfd);
	}
	return false;
}

R_API int r_debug_desc_read(RDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->h && dbg->h->desc.read) {
		return dbg->h->desc.read (fd, addr, len);
	}
	return false;
}

R_API int r_debug_desc_seek(RDebug *dbg, int fd, ut64 addr) {
	if (dbg && dbg->h && dbg->h->desc.seek) {
		return dbg->h->desc.seek (fd, addr);
	}
	return false;
}

R_API int r_debug_desc_write(RDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->h && dbg->h->desc.write) {
		return dbg->h->desc.write (fd, addr, len);
	}
	return false;
}

R_API int r_debug_desc_list(RDebug *dbg, int rad) {
	int count = 0;

	if (rad) {
		if (dbg && dbg->cb_printf) {
			dbg->cb_printf ("TODO \n");
		}
	} else {
		RListIter *iter;
		RDebugDesc *p;
		if (dbg && dbg->h && dbg->h->desc.list) {
			RList *list = dbg->h->desc.list (dbg->pid);
			r_list_foreach (list, iter, p) {
				dbg->cb_printf ("%i 0x%"PFMT64x" %c%c%c %s\n", p->fd, p->off,
						(p->perm & R_PERM_R)?'r':'-',
						(p->perm & R_PERM_W)?'w':'-',
						p->type, p->path);
			}
			r_list_purge (list);
			free (list);
		}
	}
	return count;
}
