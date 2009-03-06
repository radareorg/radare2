/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_core.h>

u64 r_core_file_resize(struct r_core_t *core, u64 newsize)
{
	if (newsize == 0 && core->file)
		return core->file->size;
	return 0LL;
}

struct r_core_file_t *r_core_file_open(struct r_core_t *r, const char *file, int mode)
{
	struct r_core_file_t *fh;
	int fd;
	char *p;

	fd = r_io_open(&r->io, file, mode, 0644);
	if (fd == -1)
		return NULL;

	fh = MALLOC_STRUCT(struct r_core_file_t);
	fh->fd = fd;
	fh->uri = strdup(file);
	fh->filename = fh->uri;
	p = strstr(fh->filename, "://");
	if (p != NULL)
		fh->filename = p+3;
	fh->rwx = mode;
	r->file = fh;
	fh->size = r_io_size(&r->io, fd);
	list_add(&(fh->list), &r->files);

	r_core_block_read(r, 0);

	return fh;
}

int r_core_file_set(struct r_core_t *r, struct r_core_file_t *fh)
{
	r->file = fh;
	return R_TRUE;
}

int r_core_file_close(struct r_core_t *r, struct r_core_file_t *fh)
{
	int ret = r_io_close(&r->io, fh->fd);
	list_del(&(fh->list));
	return ret;
}

struct r_core_file_t *r_core_file_get_fd(struct r_core_t *core, int fd)
{
	struct list_head *pos;
	list_for_each_prev(pos, &core->files) {
		struct r_core_file_t *fh = list_entry(pos, struct r_core_file_t, list);
		if (fh->fd == fd)
			return fh;
	}
	return NULL;
}

int r_core_file_close_fd(struct r_core_t *core, int fd)
{
	int ret = r_io_close(&core->io, fd);
	struct r_core_file_t *fh = r_core_file_get_fd(core, fd);
	if (fh != NULL)
		list_del(&(fh->list));
	return ret;
}
