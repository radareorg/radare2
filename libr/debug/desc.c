/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_debug.h>

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
	int count;
	// callback or rlist? i would prefer rlist here..
	RList *list = dbg->h->desc.list ();
	// TODO: loop here
	return count;
}
