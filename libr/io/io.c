/* radare - LGPL - Copyright 2008-2016 - pancake */

#include "r_io.h"
#include "r_util.h"
#include <stdio.h>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

R_LIB_VERSION (r_io);

/* allocate 128 MB */
#define R_IO_MAX_ALLOC (1024 * 1024 * 128)

// XXX: this is buggy. must use seek+read
#define USE_CACHE 1
// the new io is buggy	//liar
#define USE_NEW_IO 0
#define DO_THE_IO_DBG 0
#define IO_IFDBG if (DO_THE_IO_DBG == 1)

static ut8 *r_io_desc_read(RIO *io, RIODesc *desc, ut64 *out_sz);
static RIO *r_io_bind_get_io(RIOBind *bnd);

R_API RIO *r_io_new() {
	RIO *io = R_NEW0 (RIO);
	if (!io) {
		return NULL;
	}
	io->buffer = r_cache_new (); // RCache is a list of ranged buffers. maybe rename?
	io->write_mask_fd = -1;
	io->cb_printf = (void *)printf;
	io->bits = (sizeof (void *) == 8)? 64: 32;
	io->ff = true;
	io->Oxff = 0xff;
	io->aslr = 0;
	io->pava = false;
	io->raised = -1;
	io->autofd = true;
	r_io_map_init (io);
	r_io_desc_init (io);
	r_io_undo_init (io);
	r_io_cache_init (io);
	r_io_plugin_init (io);
	r_io_section_init (io);
	{
		char *env = r_sys_getenv ("R_IO_MAX_ALLOC");
		if (env) {
			io->maxalloc = r_num_get (NULL, env);
			free (env);
		}
	}
	return io;
}

R_API void r_io_raise(RIO *io, int fd) {
	io->raised = fd;
}

R_API int r_io_is_listener(RIO *io) {
	if (io && io->plugin && io->plugin->listener) {
		return io->plugin->listener (io->desc);
	}
	return false;
}

R_API RBuffer *r_io_read_buf(RIO *io, ut64 addr, int len) {
	RBuffer *b = R_NEW0 (RBuffer);
	if (!b) return NULL;
	b->buf = malloc (len);
	if (!b->buf) {
		free (b);
		return NULL;
	}
	len = r_io_read_at (io, addr, b->buf, len);
	b->length = (len < 0)? 0: len;
	return b;
}

R_API int r_io_write_buf(RIO *io, struct r_buf_t *b) {
	return r_io_write_at (io, b->base, b->buf, b->length);
}

R_API RIO *r_io_free(RIO *io) {
	if (!io) {
		return NULL;
	}
	R_FREE (io->plugin_default);
	r_list_free (io->plugins);
	r_list_free (io->sections);
	r_list_free (io->maps);
	r_list_free (io->undo.w_list);
	r_cache_free (io->buffer);
	r_list_free (io->cache);
	r_io_desc_fini (io);
	free (io);
	return NULL;
}

/* used by uri handler plugins */
R_API int r_io_redirect(RIO *io, const char *file) {
	free (io->redirect);
	io->redirect = file? strdup (file): NULL;
	return 0;
}

R_API RIODesc *r_io_open_as(RIO *io, const char *urihandler, const char *file, int flags, int mode) {
	RIODesc *ret;
	char *uri;
	int urilen, hlen = strlen (urihandler);
	urilen = hlen + strlen (file) + 5;
	uri = malloc (urilen);
	if (!uri)
		return NULL;
	if (hlen > 0)
		snprintf (uri, urilen, "%s://%s", urihandler, file);
	else strncpy (uri, file, urilen);
	ret = r_io_open_nomap (io, uri, flags, mode);
	free (uri);
	return ret;
}

static inline RIODesc *__getioplugin(RIO *io, const char *_uri, int flags, int mode) {
	RIOPlugin *plugin;
	RIODesc *desc = NULL;
	char *uri = strdup (_uri? _uri: "");
	char *redir = NULL;
	for (;;) {
		plugin = r_io_plugin_resolve (io, uri, 0);
		if (plugin && plugin->open) {
			desc = plugin->open (io, uri, flags, mode);
			if (io->redirect) {
				redir = uri;
				uri = strdup (io->redirect);
				r_io_redirect (io, NULL);
				continue;
			}
			if (desc) {
				desc->uri = uri;
				desc->referer = redir;
				io->plugin = plugin;
			}
		}
		break;
	}
	if (!desc) {
		plugin = r_io_plugin_get_default (io, uri, 0);
		desc = (plugin && plugin->open)
			? plugin->open (io, uri, flags, mode)
			: NULL;
		if (desc) {
			desc->uri = uri;
			io->plugin = plugin;
		}
	}
	if (!desc) {
		free (uri);
		io->plugin = NULL;
	}
	return desc;
}

static inline RList *__getioplugin_many(RIO *io, const char *_uri, int flags, int mode) {
	RIOPlugin *plugin, *iop = NULL;
	RList *list_fds = NULL;
	RListIter *iter;
	RIODesc *desc;
	char *uri = strdup (_uri);
	for (;;) {
		// resolve
		plugin = r_io_plugin_resolve (io, uri, 1);
		if (plugin && plugin->open_many) {
			// open
			list_fds = plugin->open_many (io, uri, flags, mode);
			if (io->redirect) {
				free (uri);
				uri = strdup (io->redirect);
				r_io_redirect (io, NULL);
				continue;
			}
		}
		break;
	}

	if (!list_fds) {
		free (uri);
		return NULL;
	}

	r_list_foreach (list_fds, iter, desc) {
		desc->uri = strdup (uri);
	}

	io->plugin = iop;
	free (uri);
	return list_fds;
}

R_API RIODesc *r_io_open_nomap(RIO *io, const char *file, int flags, int mode) {
	RIODesc *desc;
	if (!io || !file || io->redirect) {
		return NULL;
	}
	desc = __getioplugin (io, file, flags, mode);
	if (desc) {
		r_io_desc_add (io, desc);
		if (io->autofd || !io->desc)
			r_io_use_desc (io, desc);
	} // else eprintf ("r_io_open_nomap: Unable to open file: %s\n", file);
	return desc;
}

R_API RIODesc *r_io_open_at(RIO *io, const char *file, int flags, int mode, ut64 maddr) {
	RIODesc *desc;
	ut64 size;
	if (!io || !file || io->redirect) {
		return NULL;
	}
	desc = __getioplugin (io, file, flags, mode);
	if (desc) {
		r_io_desc_add (io, desc);
		size = r_io_desc_size (io, desc);
		if (io->autofd || !io->desc) {
			r_io_use_desc (io, desc);
		}
		r_io_map_new (io, desc->fd, mode, 0, maddr, size);
	} else {
		eprintf ("r_io_open_at: Unable to open file: %s\n", file);
	}
	return desc;
}

R_API RIODesc *r_io_open(RIO *io, const char *file, int flags, int mode) {
	return r_io_open_at (io, file, flags, mode, 0LL);
}

R_API RList *r_io_open_many(RIO *io, const char *file, int flags, int mode) {
	RIODesc *desc;
	RListIter *desc_iter = NULL;
	int fd;
	RList *list_fds;
	if (!io || !file || io->redirect)
		return NULL;
	list_fds = __getioplugin_many (io, file, flags, mode);

	if (!list_fds)
		return NULL;

	r_list_foreach (list_fds, desc_iter, desc) {
		fd = -1;
		if (desc) fd = desc->fd;
		if (fd >= 0) r_io_desc_add (io, desc);
	}
	return list_fds;
}

R_API int r_io_reopen(RIO *io, RIODesc *desc, int flags, int mode) {
	RIODesc *n = NULL;
	RListIter *iter;
	RIOMap *map;
	if (desc && desc->uri && io && io->files && (desc == r_io_desc_get (io, desc->fd))) {
		n = __getioplugin (io, desc->uri, flags, mode);
		if (!n) {
			return false;
		}
		r_io_section_rm_all (io, desc->fd);
		if (io->maps) {
			r_list_foreach (io->maps, iter, map) {
				if (map->fd == desc->fd) {
					map->fd = n->fd;
					map->flags &= n->flags;
				}
			}
		}
		if (desc->plugin && desc->plugin->close)
			desc->plugin->close (desc); //free desc->data
		free (desc->name);
		free (desc->uri);
		*desc = *n;
		free (n);
		return true;
	}
	return false;
}

R_API int r_io_use_desc(RIO *io, RIODesc *d) {
	if (io && d && d->plugin) {
		io->desc = d;
		io->plugin = d->plugin;
		return true;
	}
	return false;
}

R_API RIODesc *r_io_use_fd(RIO *io, int fd) {
	RIODesc *desc = r_io_desc_get (io, fd);
	if (!desc) return NULL;
	io->desc = desc;
	io->plugin = desc->plugin;
	return desc;
}

static bool readcache = false;

R_API int r_io_read_internal(RIO *io, ut8 *buf, int len) {
	int bytes_read = 0;
	const char *source = NULL;
	if (io->desc && io->desc->plugin && io->desc->plugin->read) {
		source = io->desc->plugin->name;
		bytes_read = io->desc->plugin->read (io, io->desc, buf, len);
#if 1
		if (readcache) {
			if (bytes_read > 0) {
				readcache = false;
				bytes_read = r_io_cache_write (io, io->off, buf, len);
				readcache = true;
			}
		}
#endif
	} else if (!io->desc) {
		if (io->files && r_list_length (io->files) != 0) {
			eprintf ("Something really bad has happened, and r2 is going to die soon. sorry! :-(\n");
		}
		source = "FAILED";
		bytes_read = 0;
	} else {
		source = "File";
		bytes_read = read (io->desc->fd, buf, len);
	}
	IO_IFDBG {
		if (io->desc) eprintf ("Data source: %s\n", io->desc->name);
		eprintf ("Asked for %d bytes, provided %d from %s\n",
			len, bytes_read, source);
	}
	return bytes_read;
}

R_API int r_io_read(RIO *io, ut8 *buf, int len) {
	int ret;
	if (!io || !io->desc || !buf || io->off == UT64_MAX)
		return -1;
	/* IGNORE check section permissions */
	if (io->enforce_rwx & R_IO_READ) {
		if (!(r_io_section_get_rwx (io, io->off) & R_IO_READ)) {
			return -1;
		}
	}
	/* io->off is in maddr, but r_io_read_at works in vaddr
	 * FIXME: in some cases, r_io_seek sets io->off in vaddr */
	ut64 vaddr = r_io_section_maddr_to_vaddr(io, io->off);
	vaddr = (vaddr == UT64_MAX) ? io->off : vaddr;
	ret = r_io_read_at (io, vaddr, buf, len);
	if (ret > 0) io->off += ret;
	return ret;
}

R_API int r_io_pread (RIO *io, ut64 paddr, ut8 *buf, int len) {
	if (!io || !buf || len < 0) {
		return -1;
	}
	if (paddr == UT64_MAX) {
		if (io->ff) {
			memset (buf, 0xff, len);
			return len;
		}
		return -1;
	}
	if (io->buffer_enabled) {
		return r_io_buffer_read (io, paddr, buf, len);
	}
	if (!io->desc || !io->desc->plugin || !io->desc->plugin->read) {
		return -1;
	}
	if (r_io_seek (io, paddr, R_IO_SEEK_SET) == UT64_MAX) {
		return -1;
	}
	return io->desc->plugin->read (io, io->desc, buf, len);
}

R_API int r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	ut64 paddr, last, last2;
	int ms, ret, l = 0, olen = len, w = 0;

	if (!io || !buf || len < 0) {
		return 0;
	}
	if (io->sectonly && !r_list_empty (io->sections)) {
		if (!r_io_section_exists_for_vaddr (io, addr, 0)) {
			// find next sec
			memset (buf, io->Oxff, len);
			ut64 next = r_io_section_next (io, addr);
			if (next < (addr + len)) {
				int delta = (next - addr);
				addr = next;
				len -= delta;
				buf += delta;
			} else {
				next = 0;
			}
			if (!next) {
				return 0;
			}
		}
	}

	io->off = addr;
	memset (buf, io->Oxff, len); // probably unnecessary

	if (io->buffer_enabled) {
		return r_io_buffer_read (io, addr, buf, len);
	}
	while (len > 0) {
		if ((addr + w) < ((addr + w) + len)) {
			// this code assumes that the IO backend knows
			// 1) the size of a loaded file and its offset into the r2 data space
			// 2) the sections with physical (offsets) and virtual addresses in r2 data space
			// Currently debuggers may not support registering these data spaces in r2 and this
			// may prevent "raw" access to locations in the data space for entities like debuggers.
			// Until that issue is resolved this code will be disabled.
			// step one does a section exist for the offset
			int exists = r_io_section_exists_for_paddr (io, addr + w, 0) ||
				r_io_section_exists_for_vaddr (io, addr + w, 0) ||
				r_io_map_exists_for_offset (io, addr + w);

			// XXX this is a break b/c external IO caller do not need to create
			// an IO Map (yet.), so the "checking existence of" only works if r_core_file
			// APIs are used to load files.
			if (!exists && r_io_map_count (io) > 0) {
				// XXX this will break if there is actually data at this location
				// or within UT64_MAX - len
				ut64 next_map_addr = UT64_MAX;
				ut64 next_sec_addr = UT64_MAX;

				RIOMap *next_map = NULL;
				RIOSection *next_sec = NULL;
				// is there a map somewhere within the next range for
				// us to read from
				next_sec = r_io_section_get_first_in_vaddr_range (io, addr + w, addr + len + w);
				next_sec_addr = next_sec? next_sec->paddr: UT64_MAX;

				if (!next_sec) {
					next_map = r_io_map_get_first_map_in_range (io, addr + w, addr + len + w);
					next_map_addr = next_map? next_map->from: UT64_MAX;
					if (len <= next_map_addr - addr)
						next_map_addr = UT64_MAX;
					else l = next_map_addr - addr;

				} else if (len <= next_map_addr - addr) {
					next_sec_addr = UT64_MAX;
				} else {
					if (addr > next_sec_addr) {
						/* avoid negative deltas */
						return olen;
					}
					l = next_sec_addr - addr;
				}

				if (!next_sec && !next_map) {
					// done
					return olen;
				}
				// want to capture monotonicity even when maps are 0 in length
				if (l == 0) l++;
				w += l;
				len -= l;
				continue;
			}

			last = r_io_section_next (io, addr + w);
			last2 = r_io_map_next (io, addr + w); // XXX: must use physical address
			if (last == (addr + w)) last = last2;
			//else if (last2<last) last = last2;
			l = (len > (last - addr + w))? (last - addr + w): len;
		} else {
			// overflow //
			l = UT64_MAX - addr + 1;
		}
		if (l < 1) l = len;
		if (addr != UT64_MAX) {
			paddr = w? r_io_section_vaddr_to_maddr_try (io, addr + w): addr;
		} else {
			paddr = 0;
		}
		if (paddr == UT64_MAX) {
			paddr = r_io_map_select (io, addr); // XXX
		}
		if (paddr == UT64_MAX) {
			w += l;
			len -= l;
			continue;
		}
		r_io_map_select (io, addr); // XXX
		if (len > 0 && l > len) l = len;
		addr = paddr - w;
		if (r_io_seek (io, paddr, R_IO_SEEK_SET) == UT64_MAX) {
			memset (buf + w, io->Oxff, l);
		}
		// XXX is this necessary?
		ms = r_io_map_select (io, addr + w);
		if (readcache) {
			if (r_io_cache_read (io, io->off, buf + w, l) == l) {
				eprintf ("CACHED\n");
				w += l;
				len -= l;
				continue;
			}
		}
		ret = r_io_read_internal (io, buf + w, l);
		if (ret < 1) {
			memset (buf + w, io->Oxff, l); // reading out of file
			ret = l;
		} else if (ret < l) {
			l = ret;
		}
		if (readcache) {
			r_io_cache_write (io, io->off, buf + w, len);
		}
#if USE_CACHE
		if (io->cached) {
			r_io_cache_read (io, addr + w, buf + w, len); //-w);
#if 0
			int cov = r_io_cache_write (io, addr+w, buf+w, len); //-w);
			if (cov != len) {
			}
#endif
		} else if (r_list_length (io->maps) > 1) {
			if (!io->debug && ms > 0) {
				//eprintf ("FAIL MS=%d l=%d d=%d\n", ms, l, d);
				/* check if address is vaddred in sections */
				ut64 o = r_io_section_maddr_to_vaddr (io, addr + w);
				if (o == UT64_MAX) {
					ut64 o = r_io_section_vaddr_to_maddr_try (io, addr + w);
					if (o == UT64_MAX) {
						memset (buf + w, io->Oxff, l);
					}
				}
				break;
			}
			//   } else {
			//eprintf ("ONT USING CACH\n");
		}
#endif
		w += l;
		len -= l;
/* Fix famous io/f bug */
#if 0
this is not a real fix, because it just avoids reading again , even if the seek returns error.
bear in mind that we need to fix that loop and honor lseek sections and sio maps fine
#endif
		if (len > 0) {
			memset (buf + w, io->Oxff, len);
		}
		//break;
	}
	return olen;
}

R_API ut64 r_io_read_i(RIO *io, ut64 addr, int sz) {
	ut64 ret = 0LL;
	ut8 buf[8];
	sz = R_DIM (sz, 1, 8);
	if (sz != r_io_read_at (io, addr, buf, sz))
		return UT64_MAX;
	memcpy ((ut8 *)&ret, buf, sz);
	return ret;
}

/* Same as r_io_read_at, but not consume bytes */
R_API int r_io_peek_at(RIO *io, const ut64 addr, ut8 *buf, const int sz) {
	int ret = -1, tmp_ret = -1;
	ret = r_io_seek (io, addr, R_IO_SEEK_SET);
	if (ret != -1) {
		ret = r_io_read (io, buf, sz);
	}
	if (ret != -1) {
		tmp_ret = r_io_seek (io, addr, R_IO_SEEK_SET);
	}
	if (tmp_ret == -1) ret = tmp_ret;
	return ret;
}

// TODO. this is a physical resize
R_API bool r_io_resize(RIO *io, ut64 newsize) {
	if (io->plugin) {
		if (io->plugin->resize && io->desc) {
			bool res = io->plugin->resize (io, io->desc, newsize);
			if (res) {
				r_io_map_truncate_update (io, io->desc->fd, newsize);
			}
			return res;
		}
		return false;
	}
	return true;
}

R_API int r_io_extend(RIO *io, ut64 size) {
	ut64 curr_off = io->off;
	ut64 cur_size = r_io_size (io), tmp_size = cur_size - size;
	ut8 *buffer = NULL;

	if (!size) {
		return false;
	}
	if (io->plugin && io->plugin->extend) {
		return io->plugin->extend (io, io->desc, size);
	}
	if (!UT64_ADD_OVFCHK (size, cur_size)) {
		if (!r_io_resize (io, size + cur_size)) {
			return false;
		}
	} else {
		return false;
	}

	if (cur_size < size) {
		tmp_size = size - cur_size;
	}

	buffer = malloc (tmp_size);
	if (!buffer) {
		return false;
	}
	// shift the bytes over by size
	(void) r_io_seek (io, curr_off, R_IO_SEEK_SET);
	r_io_read (io, buffer, tmp_size);
	// move/write the bytes
	(void) r_io_seek (io, curr_off + size, R_IO_SEEK_SET);
	r_io_write (io, buffer, tmp_size);
	// zero out new bytes
	if (cur_size < size) {
		free (buffer);
		buffer = malloc (size);
	}
	memset (buffer, 0, size);
	(void) r_io_seek (io, curr_off, R_IO_SEEK_SET);
	r_io_write (io, buffer, size);
	// reset the cursor
	(void) r_io_seek (io, curr_off, R_IO_SEEK_SET);
	free (buffer);
	return true;
}

R_API int r_io_extend_at(RIO *io, ut64 addr, ut64 size) {
	if (!size) return false;
	(void) r_io_seek (io, addr, R_IO_SEEK_SET);
	return r_io_extend (io, size);
}

R_API int r_io_set_write_mask(RIO *io, const ut8 *buf, int len) {
	if (len > 0) {
		io->write_mask_fd = io->desc->fd;
		io->write_mask_buf = (ut8 *)malloc (len);
		if (io->write_mask_buf) {
			memcpy (io->write_mask_buf, buf, len);
			io->write_mask_len = len;
			return true;
		}
	}
	io->write_mask_fd = -1;
	return false;
}

R_API int r_io_write(RIO *io, const ut8 *buf, int len) {
	ut64 maddr = io->off;
	int i, ret = -1, orig_len = 0;
	ut8 *data = NULL, *orig_bytes = NULL;

	/* check section permissions */
	if (io->enforce_rwx & R_IO_WRITE) {
		if (!(r_io_section_get_rwx (io, io->off) & R_IO_WRITE)) {
			ret = -1;
			goto cleanup;
		}
	}

	orig_bytes = malloc (len);
	if (!orig_bytes) {
		eprintf ("Cannot allocate %d bytes", len);
		ret = -1;
		goto cleanup;
	}

	orig_len = r_io_peek_at (io, io->off, orig_bytes, len);

	if (io->cached) {
		ret = r_io_cache_write (io, io->off, buf, len);
		if (ret == len) {
			if (orig_len > 0 && io->cb_core_post_write) {
				io->cb_core_post_write (io->user, maddr, orig_bytes, orig_len);
			}
			goto cleanup;
		}
		if (ret > 0) {
			len -= ret;
			buf += ret;
		}
	}

	/* TODO: implement IO cache here. to avoid dupping work on vm for example */

	/* apply write binary mask */
	if (io->write_mask_fd != -1) {
		data = (len > 0)? malloc (len): NULL;
		if (!data) {
			eprintf ("malloc failed in write_mask_fd");
			ret = -1;
			goto cleanup;
		}
		// memset (data, io->Oxff, len);
		r_io_peek_at (io, io->off, data, len);
		for (i = 0; i < len; i++) {
			data[i] = buf[i] &
				io->write_mask_buf[i % io->write_mask_len];
		}
		buf = data;
	}

	// this makes a double sub, so we restore the io->off
	{
		ut64 addr = io->off;
		r_io_map_select (io, io->off);
		io->off = addr;
	}
	{
		RIOMap *map = r_io_map_get (io, io->off);
		if (map) {
			io->off -= map->from;
		}
	}

	if (io->plugin) {
		if (io->plugin->write) {
			ret = io->plugin->write (io, io->desc, buf, len);
		} else {
			eprintf ("r_io_write: io handler with no write callback\n");
			ret = -1;
		}
	} else {
		ret = io->desc? write (io->desc->fd, buf, len): -1;
	}
	if (ret == -1) {
		if (io->cached != 2) {
			eprintf ("r_io_write: cannot write %d bytes "
				"at 0x%" PFMT64x " (file=%s, fd=%d)\n",
				len, io->off,
				io->desc? io->desc->uri: "unknown",
				io->desc? io->desc->fd: -1);
			eprintf ("hint: try oo+ or e io.cache=true\n");
			r_io_cache_invalidate (io, io->off, io->off + 1);
		}
	} else {
		if (readcache) {
			//r_io_cache_invalidate (io, io->off, io->off + len);
			r_io_cache_write (io, io->off, buf, len);
		}
		if (io->desc) {
			r_io_map_write_update (io, io->desc->fd, io->off, ret);
			io->off += ret;
		}
	}

	if (ret > 0 && orig_len > 0 && io->cb_core_post_write) {
		io->cb_core_post_write (io->user, maddr, orig_bytes, orig_len);
	}

cleanup:
	free (data);
	free (orig_bytes);

	return ret;
}

R_API int r_io_pwrite (RIO *io, ut64 paddr, const ut8 *buf, int len) {
	if (!io || !buf || paddr == UT64_MAX || len < 0) {
		return -1;
	}
	if (!io->desc || !io->desc->plugin || !io->desc->plugin->write) {
		return -1;
	}
	if (r_io_seek (io, paddr, R_IO_SEEK_SET) == UT64_MAX) {
		return -1;
	}
	return io->desc->plugin->write (io, io->desc, buf, len);
}

R_API int r_io_write_at(RIO *io, ut64 addr, const ut8 *buf, int len) {
	if (io->cached) {
		return r_io_cache_write (io, addr, buf, len);
	}
	if (r_io_seek (io, addr, R_IO_SEEK_SET) == UT64_MAX) {
		return false;
	}
	// errors on seek are checked and ignored here //
	return r_io_write (io, buf, len);
}

R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence) {
	// TODO: review the offset/vaddr/paddr/maddr thing here
	// now, io-seek always works with vaddr, because it depends on read/write ops that use it
	int posix_whence = SEEK_SET;
	ut64 ret = UT64_MAX;
	if (!io) {
		return ret;
	}
	if (io->buffer_enabled) {
		io->off = offset;
		return offset;
	}
	switch (whence) {
	case R_IO_SEEK_SET:
		posix_whence = SEEK_SET;
		break;
	case R_IO_SEEK_CUR:
		//		offset += io->off;
		posix_whence = SEEK_CUR;
		break;
	case R_IO_SEEK_END:
		//offset = UT64_MAX; // XXX: depending on io bits?
		posix_whence = SEEK_END;
		break;
	}
	// XXX: list_empty trick must be done in r_io_set_va();
	//eprintf ("-(seek)-> 0x%08llx\n", offset);
	//if (!io->debug && io->va && !r_list_empty (io->sections)) {
	if (!io->debug) {
		if (io->va && !r_list_empty (io->sections)) {
			ut64 o = r_io_section_vaddr_to_maddr_try (io, offset);
			if (o != UT64_MAX) {
				offset = o;
			}
			//	eprintf ("-(vadd)-> 0x%08llx\n", offset);
		}
	}
	// if resolution fails... just return as invalid address
	if (offset == UT64_MAX) {
		return UT64_MAX;
	}
	if (io->desc) {
		if (io->plugin && io->plugin->name && io->plugin->lseek) {
			ret = io->plugin->lseek (io, io->desc, offset, whence);
		} else {
			ret = (ut64)lseek (io->desc->fd, offset, posix_whence);
		}
	}
	if (whence == R_IO_SEEK_SET) {
		io->off = offset;
	}
#if 0
	// XXX can be problematic on w32..so no 64 bit offset?
	if (ret != UT64_MAX) {
		io->off = (whence == R_IO_SEEK_SET)
			? offset // HACKY FIX linux-arm-32-bs at 0x10000
			: ret;
			io->off = offset;
		ret = (!io->debug && io->va && !r_list_empty (io->sections))
			? r_io_section_maddr_to_vaddr (io, io->off)
			: io->off;
	}
#endif
	return ret;
}

R_API ut64 r_io_fd_size(RIO *io, int fd) {
	RIODesc *desc = r_io_desc_get (io, fd);
	return r_io_desc_size (io, desc);
}

R_API bool r_io_is_blockdevice(RIO *io) {
#if __UNIX__
	if (io && io->desc && io->desc->fd) {
		struct stat buf;
		if (io->desc->obsz) {
			return 1;
		}
		if (fstat (io->desc->fd, &buf) == -1)
			return 0;
		if (io->plugin == &r_io_plugin_default) {
			// TODO: optimal blocksize = 2048 for disk, 4096 for files
			// usually is 128K
			//	eprintf ("OPtimal blocksize: %d\n", buf.st_blksize);
			if ((buf.st_mode & S_IFCHR) == S_IFCHR) {
				io->desc->obsz = buf.st_blksize;
				return true;
			}
			return ((buf.st_mode & S_IFBLK) == S_IFBLK);
		}
	}
#endif
	return false;
}

R_API ut64 r_io_size(RIO *io) {
	int oldva;
	ut64 size, here;
	if (!io) return 0LL;
	oldva = io->va;
	if (r_io_is_listener (io)) {
		return UT64_MAX;
	}
	io->va = false;
	here = r_io_seek (io, 0, R_IO_SEEK_CUR);
	size = r_io_seek (io, 0, R_IO_SEEK_END);
	if (r_io_seek (io, here, R_IO_SEEK_SET) != here) {
		eprintf ("Failed to reset the file position\n");
	}
	io->va = oldva;
	if (r_io_is_blockdevice (io)) {
		io->va = 0;
		size = UT64_MAX;
	}
	return size;
}

R_API int r_io_system(RIO *io, const char *cmd) {
	int ret = -1;
	if (io->plugin && io->plugin->system) {
		ret = io->plugin->system (io, io->desc, cmd);
	}
	return ret;
}

R_API int r_io_plugin_close(RIO *io, RIODesc *desc) {
	if (io->plugin && io->plugin->close) {
		int ret = io->plugin->close (desc);
		if (desc == io->desc) {
			io->desc = NULL;
		}
		return ret;
	}
	return -1;
}

R_API int r_io_close(RIO *io, RIODesc *d) {
	RIODesc *cur = NULL;
	if (!io || !d) {
		return -1;
	}
	if (d != io->desc) {
		cur = io->desc;
	}
	if (r_io_use_desc (io, d)) {
		int nfd = d->fd;
		RIODesc *desc = r_io_desc_get (io, nfd);
		if (desc) {
			if (desc == io->desc) {
				cur = NULL;
			}
			r_io_map_del (io, nfd);
			r_io_section_rm_all (io, nfd);
			r_io_plugin_close (io, io->desc);
			//r_io_desc_del (io, desc->fd);
		}
		if (nfd == io->raised) {
			io->raised = -1;
		}
	}
	io->desc = cur;
	return false;
}

R_API int r_io_close_all(RIO *io) {
	// LOT OF MEMLEAKS HERE
	if (!io) {
		return 0;
	}
	r_cache_free (io->buffer);
	io->buffer = r_cache_new (); // RCache is a list of ranged buffers. maybe rename?
	io->write_mask_fd = -1;
	io->ff = 1;
	io->raised = -1;
	io->autofd = true;
	r_io_map_del (io, -1);
	r_io_desc_del (io, -1);
	r_io_section_rm_all (io, -1);
	r_io_undo_init (io);
	r_io_cache_reset (io, 0);
	//	r_io_plugin_init (io);
	return 1;
}

R_API int r_io_bind(RIO *io, RIOBind *bnd) {
	bnd->io = io;
	bnd->init = true;
	bnd->get_io = r_io_bind_get_io;
	bnd->read_at = r_io_read_at;
	bnd->write_at = r_io_write_at;
	bnd->size = r_io_size;
	bnd->seek = r_io_seek;
	bnd->system = r_io_system;
	bnd->is_valid_offset = r_io_is_valid_offset;

	bnd->desc_open = r_io_open_nomap;
	bnd->desc_open_at = r_io_open_at;
	bnd->desc_close = r_io_close;
	bnd->desc_read = r_io_desc_read;
	bnd->desc_size = r_io_desc_size;
	bnd->desc_seek = r_io_desc_seek;
	bnd->desc_get_by_fd = r_io_desc_get;

	bnd->section_add = r_io_section_add;
	bnd->section_vget = r_io_section_vget;

	bnd->section_set_arch = r_io_section_set_archbits;
	bnd->section_set_arch_bin_id = r_io_section_set_archbits_bin_id;

	return true;
}

R_API int r_io_accept(RIO *io, int fd) {
	if (r_io_is_listener (io) && io->plugin && io->plugin->accept) {
		return io->plugin->accept (io, io->desc, fd);
	}
	return false;
}

/* moves bytes up (+) or down (-) within the specified range */
R_API int r_io_shift(RIO *io, ut64 start, ut64 end, st64 move) {
	ut8 *buf;
	ut64 chunksize = 0x10000;
	ut64 rest, src, shiftsize = r_num_abs (move);
	if (!shiftsize || (end - start) <= shiftsize) return false;
	rest = (end - start) - shiftsize;

	if (!(buf = malloc (chunksize))) {
		return false;
	}
	if (move > 0) {
		src = end - shiftsize;
	} else {
		src = start + shiftsize;
	}
	while (rest > 0) {
		if (chunksize > rest) {
			chunksize = rest;
		}
		if (move > 0) {
			src -= chunksize;
		}
		r_io_read_at (io, src, buf, chunksize);
		r_io_write_at (io, src + move, buf, chunksize);
		if (move < 0) {
			src += chunksize;
		}
		rest -= chunksize;
	}
	free (buf);
	return true;
}

R_API int r_io_create(RIO *io, const char *file, int mode, int type) {
	if (io->plugin && io->plugin->create) {
		return io->plugin->create (io, file, mode, type);
	}
	if (type == 'd' || type == 1) {
		return r_sys_mkdir (file);
	}
	return r_sandbox_creat (file, mode);
}

R_API void r_io_sort_maps(RIO *io) {
	r_list_sort (io->maps, (RListComparator)r_io_map_sort);
}

// THIS IS pread.. a weird one
static ut8 *r_io_desc_read(RIO *io, RIODesc *desc, ut64 *out_sz) {
	ut8 *buf = NULL;
	ut64 off = 0;

	if (!io || !out_sz) {
		return NULL;
	}
	if (!desc) {
		desc = io->desc;
	}
	if (*out_sz == UT64_MAX) {
		*out_sz = r_io_desc_size (io, desc);
	}
	if (*out_sz == 0x8000000) {
		*out_sz = 1024 * 1024 * 1; // 2MB
	}
	off = io->off;
	if (*out_sz == UT64_MAX) {
		return NULL;
	}
	if (io->maxalloc && *out_sz > io->maxalloc) {
		eprintf ("WARNING: File is greater than 0x%"PFMT64x" bytes.\n"
				"Allocating R_IO_MAX_ALLOC set as the environment variable.\n", io->maxalloc);
		*out_sz = io->maxalloc;
	}
	buf = malloc (*out_sz + 1);
	if (!buf) {
		return NULL;
	}
	buf[*out_sz] = 0;
	if (!buf) {
		if (*out_sz > R_IO_MAX_ALLOC) {
			char *num_unit = r_num_units (NULL, *out_sz);
			eprintf ("Failed to allocate %s bytes.\n"
				"Allocating %"PFMT64u" bytes.\n",
				num_unit, (ut64)R_IO_MAX_ALLOC);
			free (num_unit);
			*out_sz = R_IO_MAX_ALLOC;
			buf = malloc (*out_sz + 1);
			buf[*out_sz] = 0;
		}
		if (!buf) {
			char *num_unit = r_num_units (NULL, *out_sz);
			eprintf ("Failed to allocate %s bytes.\n", num_unit);
			free (num_unit);
			return NULL;
		}
	}
	if (buf && desc->plugin && desc->plugin->read) {
		if (!buf || !desc->plugin->read (io, desc, buf, *out_sz)) {
			free (buf);
			io->off = off;
			return NULL;
		}
	}
	io->off = off;
	return buf;
}

static RIO *r_io_bind_get_io(RIOBind *bnd) {
	return bnd? bnd->io: NULL;
}

// check if reading at offset or writting to offset is reasonable
R_API int r_io_is_valid_offset(RIO *io, ut64 offset, int hasperm) {
	if (!io) {
		eprintf ("r_io_is_valid_offset: io is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
	bool io_sectonly = io->sectonly;
	bool io_va = io->va;
	if (!io->files) {
		eprintf ("r_io_is_valid_offset: io->files is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
	if (r_list_empty (io->files)) {
		return false;
	}
	if (!io->desc) {
		eprintf ("r_io_is_valid_offset: io->desc is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
#if 0
if (hasperm) {
	int ret = (r_io_map_exists_for_offset (io, offset) ||
			r_io_section_exists_for_vaddr (io, offset, hasperm));
}
#endif
	if (r_list_empty (io->sections)) {
		if ((r_io_map_exists_for_offset (io, offset))) {
			return true;
		}
	}
	if (!io_va) {
		if ((r_io_map_exists_for_offset (io, offset))) {
			return true;
		}
		return (offset < r_io_size (io));
	}
	if (io->debug) {
		// TODO check debug maps here
		return true;
	}
	if (io_sectonly) {
		if (r_list_empty (io->sections)) {
			return true;
		}
		return (r_io_map_exists_for_offset (io, offset) ||
			r_io_section_exists_for_vaddr (io, offset, hasperm));
	}
	if (!io_va && r_io_map_exists_for_offset (io, offset)) {
		return true;
	}
	return r_io_section_exists_for_vaddr (io, offset, hasperm);
}
