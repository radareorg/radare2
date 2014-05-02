/* radare - LGPL - Copyright 2010-2013 - pancake */

// XXX: All this stuff must be linked to the code injection api

#include <r_debug.h>

R_API RDebugDesc *r_debug_desc_new (int fd, char* path, int perm, int type, int off) {
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

R_API void r_debug_desc_free (RDebugDesc *p) {
	if (p) {
		if (p->path)
			free (p->path);
		free (p);
	}
}

R_API int r_debug_desc_open(RDebug *dbg, const char *path) {
	if (dbg && dbg->h && dbg->h->desc.open)
		return dbg->h->desc.open (path);
	return R_FALSE;
}

R_API int r_debug_desc_close(RDebug *dbg, int fd) {
	if (dbg && dbg->h && dbg->h->desc.close)
		return dbg->h->desc.close (fd);
	return R_FALSE;
}

R_API int r_debug_desc_dup(RDebug *dbg, int fd, int newfd) {
	if (dbg && dbg->h && dbg->h->desc.dup)
		return dbg->h->desc.dup (fd, newfd);
	return R_FALSE;
}

R_API int r_debug_desc_read(RDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->h && dbg->h->desc.read)
		return dbg->h->desc.read (fd, addr, len);
	return R_FALSE;
}

R_API int r_debug_desc_seek(RDebug *dbg, int fd, ut64 addr) {
	if (dbg && dbg->h && dbg->h->desc.seek)
		return dbg->h->desc.seek (fd, addr);
	return R_FALSE;
}

R_API int r_debug_desc_write(RDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->h && dbg->h->desc.write)
		return dbg->h->desc.write (fd, addr, len);
	return R_FALSE;
}

R_API int r_debug_desc_list(RDebug *dbg, int rad) {
	int count = 0;
	RList *list;
	RListIter *iter;
	RDebugDesc *p;

	if (rad) {
		if (dbg && dbg->printf)
			dbg->printf ("TODO \n");
	} else {
		if (dbg && dbg->h && dbg->h->desc.list) {
			list = dbg->h->desc.list (dbg->pid);
			r_list_foreach (list, iter, p) {
				dbg->printf ("%i 0x%"PFMT64x" %c%c%c %s\n", p->fd, p->off,
						(p->perm & R_IO_READ)?'r':'-',
						(p->perm & R_IO_WRITE)?'w':'-',
						p->type, p->path);
			}
			r_list_purge (list);
			free (list);
		}
	}
	return count;
}
