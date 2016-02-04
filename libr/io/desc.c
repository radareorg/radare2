#include <r_io.h>
#include <sdb.h>
#include <string.h>

R_API int r_io_desc_init (RIO *io)
{
	if (!io || io->files)
		return false;
	io->files = sdb_new0 ();
	io->desc_fd = 2;
	return true;
}

//shall be used by plugins for creating descs
R_API RIODesc *r_io_desc_new (RIO *io, RIOPlugin *plugin, char *uri, int flags, int mode, void *data)	//XXX kill mode
{
	RIODesc *desc = NULL;
	if (!io || !plugin || !uri)
		return NULL;
	desc = R_NEW0 (RIODesc);
	if (io->freed_desc_fds && io->freed_desc_fds->length) {
		desc->fd = (int)(size_t) ls_pop (io->freed_desc_fds);
		if (!io->freed_desc_fds->length) {
			ls_free (io->freed_desc_fds);
			io->freed_desc_fds = NULL;
		}
	} else if (io->desc_fd != 0xffffffff) {
		io->desc_fd++;
		desc->fd = io->desc_fd;
	}
	desc->io = io;
	desc->plugin = plugin;
	desc->data = data;
	desc->flags = flags;
	desc->uri = strdup (uri);			//because the uri-arg may live on the stack
	return desc;
}

R_API void r_io_desc_free (RIODesc *desc)
{
	if (desc) {
		free (desc->uri);
		free (desc->referer);
		free (desc->name);
		if (desc->io && (desc->fd > 2)) {
			if (desc->fd == desc->io->desc_fd) {
				desc->io->desc_fd--;
			} else {
				if (!desc->io->freed_desc_fds) {
					desc->io->freed_desc_fds = ls_new ();
					desc->io->freed_desc_fds->free = NULL;
				}
				ls_prepend (desc->io->freed_desc_fds, (void *)(size_t)desc->fd);
			}
		}
//		free (desc->plugin);
	}
	free (desc);
}

R_API int r_io_desc_add (RIO *io, RIODesc *desc)
{
	char s[64];
	if (!io || !io->files || !desc)
		return false;
	desc->io = io;							//just for the case when plugins cannot use r_io_desc_new
	sdb_itoa ((ut64)desc->fd, s, 10);
	if ((desc->fd > io->desc_fd) || sdb_num_exists (io->files, s)) { //check if fd already exists in db
		eprintf ("You are using this API incorrectly\n");
		return false;
	}
	sdb_num_set (io->files, s, (ut64)desc, 0);
	return sdb_num_exists (io->files, s);				//check if storage worked
}

R_API int r_io_desc_del (RIO *io, int fd)
{
	char s[64];
	if (!io || !io->files)
		return false;
	sdb_itoa ((ut64)fd, s, 10);
	r_io_desc_free ((RIODesc *)sdb_num_get (io->files, s, NULL));
	if ((ut64)io->desc == sdb_num_get (io->files, s, NULL))
		io->desc = NULL;					//prevent evil segfaults
	return sdb_unset (io->files, s, 0);
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
		return false;
	io->desc = desc;
	return true;
}

R_API ut64 r_io_desc_seek (RIODesc *desc, ut64 offset, int whence)
{
	if (!desc || !desc->plugin || !desc->plugin->lseek)
		return (ut64)-1;
	return desc->plugin->lseek (desc->io, desc, offset, whence);
}

R_API ut64 r_io_desc_size (RIODesc *desc)
{
	ut64 off, ret;
	if (!desc || !desc->plugin || !desc->plugin->lseek)
		return 0LL;
	off = desc->plugin->lseek (desc->io, desc, 0LL, R_IO_SEEK_CUR);
	ret = desc->plugin->lseek (desc->io, desc, 0LL, R_IO_SEEK_END);
	desc->plugin->lseek (desc->io, desc, off, R_IO_SEEK_CUR);			//what to do if that seek fails?
	return ret;
}

R_API bool r_io_desc_exchange (RIO *io, int fd, int fdx)
{
	char s[64];
	RIODesc *desc, *descx;
	SdbListIter *iter;
	RIOMap *map;
	if (!(desc = r_io_desc_get (io, fd)) ||
		!(descx = r_io_desc_get (io, fdx)) ||
		!io->maps)
			return false;
	desc->fd = fdx;
	descx->fd = fd;
	sdb_itoa ((ut64)desc->fd, s, 10);
	sdb_num_set (io->files, s, (ut64)desc, 0);
	sdb_itoa ((ut64)descx->fd, s, 10);
	sdb_num_set (io->files, s, (ut64)descx, 0);
	if (io->p_cache) {
		Sdb *cache = desc->cache;
		desc->cache = descx->cache;
		descx->cache = cache;
		r_io_desc_cache_cleanup (desc);
		r_io_desc_cache_cleanup (descx);
	}
	ls_foreach (io->maps, iter, map) {
		if (map->fd == fdx) {
			map->flags &= (desc->flags | R_IO_EXEC);
		} else if (map->fd == fd) {
			map->flags &= (descx->flags | R_IO_EXEC);
		}
	}
	return true;
}

int desc_fini_cb (void *user, const char *fd, const char *cdesc)
{
//	RIO *io = (RIO *)user;							//unused
	RIODesc *desc = (RIODesc *)(size_t)sdb_atoi (cdesc);
	if (!desc)
		return true;
	if (desc->plugin && desc->plugin->close)
		desc->plugin->close (desc);
	r_io_desc_free (desc);
	return true;
}

//closes all descs and frees all descs and io->files
R_API int r_io_desc_fini (RIO *io)
{
	int ret;
	if (!io || !io->files)
		return false;
	ret = sdb_foreach (io->files, desc_fini_cb, io);
	sdb_free (io->files);
	io->files = NULL;
	io->desc = NULL;							//no map-cleanup here, to keep it modular useable
	return ret;
}
