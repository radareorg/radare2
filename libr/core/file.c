/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_core.h>

R_API ut64 r_core_file_resize(struct r_core_t *core, ut64 newsize) {
	if (newsize==0 && core->file)
		return core->file->size;
	return 0LL;
}

R_API struct r_core_file_t *r_core_file_open(struct r_core_t *r, const char *file, int mode) {
	struct r_core_file_t *fh;
	const char *cp;
	char *p;
	int fd;

	fd = r_io_open (&r->io, file, mode, 0644);
	if (fd == -1)
		return NULL;

	fh = MALLOC_STRUCT (RCoreFile);
	fh->fd = fd;
	fh->uri = strdup (file);
	fh->filename = fh->uri;
	p = strstr (fh->filename, "://");
	if (p != NULL)
		fh->filename = p+3;
	fh->rwx = mode;
	r->file = fh;
	fh->size = r_io_size(&r->io, fd);
	list_add (&(fh->list), &r->files);

	r_bin_load (&r->bin, fh->filename, NULL);

	r_core_block_read (r, 0);

	cp = r_config_get (&r->config, "cmd.open");
	if (cp && *cp)
		r_core_cmd (r, cp, 0);
	return fh;
}

R_API int r_core_file_set(struct r_core_t *r, struct r_core_file_t *fh) {
	r->file = fh;
	return R_TRUE;
}

R_API int r_core_file_close(struct r_core_t *r, struct r_core_file_t *fh) {
	int ret = r_io_close (&r->io, fh->fd);
	list_del (&(fh->list));
	// TODO: set previous opened file as current one
	return ret;
}

R_API struct r_core_file_t *r_core_file_get_fd(struct r_core_t *core, int fd) {
	struct list_head *pos;
	list_for_each_prev (pos, &core->files) {
		RCoreFile *file = list_entry (pos, RCoreFile, list);
		if (file->fd == fd)
			return file;
	}
	return NULL;
}

R_API int r_core_file_list(struct r_core_t *core) {
	int count = 0;
	struct list_head *pos;
	list_for_each_prev (pos, &core->files) {
		RCoreFile *f = list_entry (pos, RCoreFile, list);
		eprintf (" %d %s\n", f->fd, f->uri);
		count++;
	}
	return count;
}

R_API int r_core_file_close_fd(struct r_core_t *core, int fd) {
	int ret = r_io_close (&core->io, fd);
	struct r_core_file_t *fh = r_core_file_get_fd (core, fd);
	if (fh != NULL)
		list_del (&(fh->list));
	return ret;
}
