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
	r_return_val_if_fail (dbg && dbg->current, -1);
	if (dbg && dbg->current && dbg->current->plugin.desc.open) {
		return dbg->current->plugin.desc.open (path);
	}
	return -1;
}

R_API int r_debug_desc_close(RDebug *dbg, int fd) {
	if (dbg && dbg->current && dbg->current->plugin.desc.close) {
		return dbg->current->plugin.desc.close (fd);
	}
	return false;
}

R_API int r_debug_desc_dup(RDebug *dbg, int fd, int newfd) {
	if (dbg && dbg->current && dbg->current->plugin.desc.dup) {
		return dbg->current->plugin.desc.dup (fd, newfd);
	}
	return false;
}

R_API int r_debug_desc_read(RDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->current && dbg->current->plugin.desc.read) {
		return dbg->current->plugin.desc.read (fd, addr, len);
	}
	return false;
}

R_API int r_debug_desc_seek(RDebug *dbg, int fd, ut64 addr) {
	if (dbg && dbg->current && dbg->current->plugin.desc.seek) {
		return dbg->current->plugin.desc.seek (fd, addr);
	}
	return false;
}

R_API int r_debug_desc_write(RDebug *dbg, int fd, ut64 addr, int len) {
	if (dbg && dbg->current && dbg->current->plugin.desc.write) {
		return dbg->current->plugin.desc.write (fd, addr, len);
	}
	return false;
}

R_API int r_debug_desc_list(RDebug *dbg, bool show_commands) {
	RListIter *iter;
	RDebugDesc *p;
	int count = 0;

	if (dbg && dbg->current && dbg->current->plugin.desc.list) {
		RList *list = dbg->current->plugin.desc.list (dbg->pid);
		r_list_foreach (list, iter, p) {
			if (show_commands) {
				// Skip over std streams
				// TODO: option to select which fd to start at?
				if (p->fd < 3) {
					dbg->cb_printf ("#dd %s\n", p->path);
				} else {
					dbg->cb_printf ("dd %s\n", p->path);
				}
			} else {
				dbg->cb_printf ("%d 0x%" PFMT64x " %c%c%c %s\n", p->fd, p->off,
						(p->perm & R_PERM_R)? 'r': '-',
						(p->perm & R_PERM_W)? 'w': '-',
						p->type, p->path);
			}
		}
		r_list_free (list);
	}
	return count;
}
