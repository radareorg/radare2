#include <r_io.h>
#include <sdb.h>
#include <string.h>

R_API int r_io_desc_init (RIO *io)
{
	if (!io || io->files)
		return R_FALSE;
	io->files = sdb_new0 ();
	return R_TRUE;
}

R_API RIODesc *r_io_desc_new (RIOCbs *cbs, int fd, char *uri, int flags, void *data)
{
	RIODesc *desc = NULL;
	if (!cbs || !uri)
		return NULL;
	desc = R_NEW0 (RIODesc);
	desc->cbs = cbs;
	desc->fd = fd;
	desc->data = data;
	desc->flags = flags;
	desc->uri = strdup (uri);			//because the uri-arg may live on the stack
	return desc;
}

R_API void r_io_desc_free (RIODesc *desc)
{
	if (desc) {
		free (desc->uri);
//		free (desc->cbs);
	}
	free (desc);
}

R_API int r_io_desc_add (RIO *io, RIODesc *desc)
{
	char s[64];
	if (!io || !io->files || !desc)
		return R_FALSE;
	sdb_itoa ((ut64)desc->fd, s, 10);
	if (sdb_num_exists (io->files, s))		//check if fd already exists in db
		return R_FALSE;
	sdb_num_set (io->files, s, (ut64)desc, 0);
	return sdb_num_exists (io->files, s);		//check if storage worked
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
R_API int r_io_desc_del(RIO *io, int fd) {
	RListIter *iter;
	RIODesc *d;
	io->desc = NULL;
	if (!r_list_empty (io->files)) {
		io->desc = r_list_first (io->files);
	}
	/* No _safe loop necessary because we return immediately after the delete. */
	r_list_foreach (io->files, iter, d) {
		if (d->fd == fd || fd == -1) {
			r_io_desc_free (d);
			iter->data = NULL; // enforce free
			r_list_delete (io->files, iter);
			return true;
		}
	}
	return false;
=======
R_API int r_io_desc_del (RIO *io, int fd)
{
	char s[64];
	if (!io || !io->files)
		return R_FALSE;
	sdb_itoa ((ut64)fd, s, 10);
	r_io_desc_free ((RIODesc *)sdb_num_get (io->files, s, NULL));
	if ((ut64)io->desc == sdb_num_get (io->files, s, NULL))
		io->desc = NULL;					//prevent evil segfaults
	return sdb_unset (io->files, s, 0);
>>>>>>> so it begins
}

R_API RIODesc *r_io_desc_get (RIO *io, int fd)
{
	char s[64];
	if (!io || !io->files)
		return NULL;
	sdb_itoa ((ut64)fd, s, 10);
	return (RIODesc *)sdb_num_get (io->files, s, NULL);
}

R_API int r_io_desc_use (RIO *io, int fd)
{
	RIODesc *desc;
	if (!(desc = r_io_desc_get (io, fd)))
		return R_FALSE;
	io->desc = desc;
	return R_TRUE;
}

R_API ut64 r_io_desc_seek (RIODesc *desc, ut64 offset, int whence)
{
	if (!desc || !desc->cbs || !desc->cbs->lseek)
		return (ut64)-1;
	return desc->cbs->lseek (desc->io, desc, offset, whence);
}

R_API ut64 r_io_desc_size (RIODesc *desc)
{
	ut64 off, ret;
	if (desc || !desc->cbs || !desc->cbs->lseek)
		return 0LL;
	off = desc->cbs->lseek (desc->io, desc, 0LL, R_IO_SEEK_CUR);
	ret = desc->cbs->lseek (desc->io, desc, 0LL, R_IO_SEEK_END);
	desc->cbs->lseek (desc->io, desc, off, R_IO_SEEK_CUR);			//what to do if that seek fails?
	return ret;
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
R_API void r_io_desc_list_visual(RIO *io, ut64 seek, ut64 len, int width, int use_color) {
	ut64 mul, min = -1, max = -1;
	RListIter *iter;
	RIOMap *s;
	int j, i;

	width -= 52;
	if (width<1)
		width = 30;

	seek = (io->va || io->debug) ? r_io_section_vaddr_to_maddr_try (io, seek) : seek;

	r_list_foreach (io->maps, iter, s) {
		if (min == -1 || s->from< min)
			min = s->from;
		if (max == -1 || s->to > max)
			max = s->to;
	}
=======
int desc_fini_cb (void *user, const char *fd, const char *cdesc)
{
//	RIO *io = (RIO *)user;							//unused
	RIODesc *desc = (RIODesc *)(size_t)sdb_atoi (cdesc);
	if (!desc)
		return R_TRUE;
	if (desc->cbs && desc->cbs->close)
		desc->cbs->close (desc);
	r_io_desc_free (desc);
	return R_TRUE;
}
>>>>>>> so it begins

//closes all descs and frees all descs and io->files
R_API int r_io_desc_fini (RIO *io)
{
	int ret;
	if (!io || !io->files)
		return R_FALSE;
	ret = sdb_foreach (io->files, desc_fini_cb, io);
	sdb_free (io->files);
	io->files = NULL;
	io->desc = NULL;							//no map-cleanup here, to keep it modular useable
	return ret;
}
