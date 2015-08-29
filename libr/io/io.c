#include <r_io.h>
#include <sdb.h>

void operate_on_itermap (SdbListIter *iter, RIO *io, ut64 vaddr, ut8 *buf, int len, int match_flg, int (op (RIO *io, ut64 addr, ut8 *buf, int len)));

R_API RIO *r_io_new ()
{
	RIO *ret = R_NEW0 (RIO);
	return r_io_init (ret);
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
R_API RIO *r_io_new() {
	RIO *io = R_NEW0 (RIO);
	if (!io) return NULL;
	io->buffer = r_cache_new (); // RCache is a list of ranged buffers. maybe rename?
	io->write_mask_fd = -1;
	io->cb_printf = (void*) printf;
	io->bits = (sizeof(void*) == 8)? 64: 32;
	io->ff = 1;
	io->aslr = 0;
	io->raised = -1;
	io->autofd = true;
	r_io_map_init (io);
=======
R_API RIO *r_io_init (RIO *io)
{
	if (!io)
		return NULL;
>>>>>>> so it begins
	r_io_desc_init (io);
	r_io_map_init (io);
	return io;
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
R_API void r_io_raise(RIO *io, int fd) {
	io->raised = fd;
}

R_API int r_io_is_listener(RIO *io) {
	if (io && io->plugin && io->plugin->listener)
		return io->plugin->listener (io->desc);
	return false;
}

R_API RBuffer *r_io_read_buf(RIO *io, ut64 addr, int len) {
	RBuffer *b = R_NEW0 (RBuffer);
	b->buf = malloc (len);
	len = r_io_read_at (io, addr, b->buf, len);
	b->length = (len<0)?0:len;
	return b;
}

R_API int r_io_write_buf(RIO *io, struct r_buf_t *b) {
	return r_io_write_at (io, b->base, b->buf, b->length);
}

R_API RIO *r_io_free(RIO *io) {
	struct list_head *pos, *n;
	if (!io) return NULL;
	/* TODO: properly free inner nfo */
	/* TODO: memory leaks */
	list_for_each_safe (pos, n, &io->io_list) {
		struct r_io_list_t *il = list_entry (pos, struct r_io_list_t, list);
		R_FREE (il->plugin);
		list_del (pos);
		R_FREE (il);
	}
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
	urilen = hlen + strlen (file)+5;
	uri = malloc (urilen);
	if (uri == NULL)
=======
R_API RIODesc *r_io_open_nomap (RIO *io, RIOCbs *cbs, char *uri, int flags, int mode)
{
	RIODesc *desc;
	if (!io || !io->files || !cbs || !cbs->open || !cbs->close || !uri)
>>>>>>> so it begins
		return NULL;
	desc = cbs->open (io, uri, flags, mode);
	if (!desc)
		return NULL;
	if (!desc->cbs)						//for none static callbacks, those that cannot use r_io_desc_new
		desc->cbs = cbs;
	r_io_desc_add (io, desc);
	if (io->autofd || !io->desc)				//set desc as current if autofd or io->desc==NULL
		io->desc = desc;
	return desc;
}

R_API RIODesc *r_io_open (RIO *io, RIOCbs *cbs, char *uri, int flags, int mode)
{
	RIODesc *desc;
	if (!io || !io->maps)
		return NULL;
	desc = r_io_open_nomap (io, cbs, uri, flags, mode);
	if (!desc)
		return NULL;
	r_io_map_new (io, desc->fd, desc->flags, 0LL, 0LL, r_io_desc_size (desc));
	return desc;
}

R_API RIODesc *r_io_open_at (RIO *io, RIOCbs *cbs, char *uri, int flags, int mode, ut64 at)
{
	RIODesc *desc;
	ut64 size;
	if (!io || !io->maps)
		return NULL;
	desc = r_io_open_nomap (io, cbs, uri, flags, mode);
	if (!desc)
		 return NULL;
	size = r_io_desc_size (desc);
	if (size && ((UT64_MAX - size + 1) < at)) {									//second map
		r_io_map_new (io, desc->fd, desc->flags, UT64_MAX - at + 1, 0LL, size - (UT64_MAX - at) - 1);	//split map into 2 maps if only 1 big map results into interger overflow
		size = UT64_MAX - at + 1;										//someone pls take a look at this confusing stuff
	}
	r_io_map_new (io, desc->fd, desc->flags, 0LL, at, size);								//first map
	return desc;
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
R_API RIODesc *r_io_open (RIO *io, const char *file, int flags, int mode) {
	return r_io_open_at (io, file, flags, mode, 0LL);
}

R_API RList *r_io_open_many(RIO *io, const char *file, int flags, int mode) {
	RIODesc *desc;
	RListIter *desc_iter = NULL;
	int fd;
	RList *list_fds;
	if (io->redirect)
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

R_API int r_io_reopen (RIO *io, RIODesc *desc, int flags, int mode) {
	RIODesc *n = NULL;
	RListIter *iter;
	RIOMap *map;
	if (desc && desc->uri && io && io->files && (desc == r_io_desc_get (io, desc->fd))) {
		n = __getioplugin (io, desc->uri, flags, mode);
		if (!n)
			return false;
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
			desc->plugin->close (desc);		//free desc->data
		free (desc->name);
		free (desc->uri);
		*desc = *n;
		free (n);
		return true;
	}
	return false;
}

R_API int r_io_use_desc (RIO *io, RIODesc *d) {
	if (d) {
		io->desc = d;
		io->plugin = d->plugin;
		return true;
	}
	return false;
}

R_API RIODesc *r_io_use_fd (RIO *io, int fd) {
=======
R_API int r_io_close (RIO *io, int fd)
{
>>>>>>> so it begins
	RIODesc *desc = r_io_desc_get (io, fd);
	if (!desc || !desc->cbs || !desc->cbs->close)										//check for cb
		return R_FALSE;
	if (!desc->cbs->close (desc))												//close fd
		return R_FALSE;
	r_io_desc_del (io, fd);													//remove entry from sdb-instance and free the desc-struct
	r_io_map_cleanup (io);													//remove all dead maps
	return R_TRUE;
}

R_API int r_io_pread_at (RIO *io, ut64 paddr, ut8 *buf, int len)
{
	if (!io || !buf)
		return 0;
	if (io->ff)
		memset (buf, 0xff, len);
	if (!io->desc || !(io->desc->flags & R_IO_READ) || !io->desc->cbs || !io->desc->cbs->read || !len)			//check pointers and permissions
		return 0;
<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
	if (io->vio)
		return r_io_read_cr (io, addr, buf, len);
	if (io->sectonly && !r_list_empty (io->sections)) {
		if (!r_io_section_exists_for_vaddr (io, addr, 0)) {
			// find next sec
			memset (buf, 0xff, len);
			ut64 next = r_io_section_next (io, addr);
			if (next < (addr+len)) {
				int delta = (next-addr);
				addr = next;
				len -= delta;
				buf += delta;
			} else next = 0;
			if (!next)
				return 0;
		}
	}

	if (io->raw) {
		if (r_io_seek (io, addr, R_IO_SEEK_SET) == UT64_MAX)
			memset (buf, 0xff, len);
		return r_io_read_internal (io, buf, len);
	}

	io->off = addr;
	memset (buf, 0xff, len); // probably unnecessary

	if (io->buffer_enabled) {
		return r_io_buffer_read (io, addr, buf, len);
	}
	while (len>0) {
		if ((addr+w)< ((addr+w)+len)) {
			// this code assumes that the IO backend knows
			// 1) the size of a loaded file and its offset into the r2 data space
			// 2) the sections with physical (offsets) and virtual addresses in r2 data space
			// Currently debuggers may not support registering these data spaces in r2 and this
			// may prevent "raw" access to locations in the data space for entities like debuggers.
			// Until that issue is resolved this code will be disabled.
			// step one does a section exist for the offset
			int exists = r_io_section_exists_for_paddr (io, addr+w, 0) ||
				r_io_section_exists_for_vaddr (io, addr+w, 0) ||
				r_io_map_exists_for_offset (io, addr+w);

			// XXX this is a break b/c external IO caller do not need to create
			// an IO Map (yet.), so the "checking existence of" only works if r_core_file
			// APIs are used to load files.
			if (!exists && r_io_map_count (io) > 0) {
				// XXX this will break if there is actually data at this location
				// or within UT64_MAX - len
				ut64 next_map_addr = UT64_MAX,
				     next_sec_addr = UT64_MAX;

				RIOMap *next_map = NULL;
				RIOSection * next_sec = NULL;
				// is there a map somewhere within the next range for
				// us to read from
				next_sec = r_io_section_get_first_in_vaddr_range (io, addr+w, addr+len+w);
				next_sec_addr = next_sec ? next_sec->offset : UT64_MAX;

				if (!next_sec) {
					next_map = r_io_map_get_first_map_in_range (io, addr+w, addr+len+w);
					next_map_addr = next_map ? next_map->from : UT64_MAX;
					if (len <= next_map_addr-addr) next_map_addr = UT64_MAX;
					else l = next_map_addr-addr;

				} else if (len <= next_map_addr-addr) {
					next_sec_addr = UT64_MAX;
				} else {
					if (addr > next_sec_addr) {
						/* avoid negative deltas */
						return olen;
					}
					l = next_sec_addr-addr;
				}

				if (!next_sec && !next_map) {
					// done
					return olen;
				}
				// want to capture monotonicity even when maps are 0 in length
				if (l==0) l++;
				w+= l;
				len -= l;
				continue;
			}

			last = r_io_section_next (io, addr+w);
			last2 = r_io_map_next (io, addr+w); // XXX: must use physical address
			if (last == (addr+w)) last = last2;
			//else if (last2<last) last = last2;
			l = (len > (last-addr+w))? (last-addr+w): len;
		} else {
			// overflow //
			l = UT64_MAX - addr + 1;
		}
		if (l<1) {
			l = len;
		}
		if (addr != UT64_MAX) {
			paddr = w? r_io_section_vaddr_to_maddr_try (io, addr+w): addr;
		} else paddr = 0;
		//if (!paddr || paddr==UT64_MAX)
		if (paddr==UT64_MAX) {
			paddr = r_io_map_select (io, addr); // XXX
		}
		if (paddr == UT64_MAX) {
			w +=l;
			len -= l;
			continue;
		}
		r_io_map_select (io, addr); // XXX
		if (len>0 && l>len) l = len;
		addr = paddr-w;
		if (r_io_seek (io, paddr, R_IO_SEEK_SET)==UT64_MAX) {
			memset (buf+w, 0xff, l);
		}
		// XXX is this necessary?
		ms = r_io_map_select (io, addr+w);
		ret = r_io_read_internal (io, buf+w, l);
		if (ret<1) {
			memset (buf+w, 0xff, l); // reading out of file
			ret = l;
		} else if (ret<l) {
			l = ret;
		}
#if USE_CACHE
		if (io->cached) {
			r_io_cache_read (io, addr+w, buf+w, len); //-w);
		} else if (r_list_length (io->maps) >1) {
			if (!io->debug && ms>0) {
				//eprintf ("FAIL MS=%d l=%d d=%d\n", ms, l, d);
				/* check if address is vaddred in sections */
				ut64 o = r_io_section_maddr_to_vaddr (io, addr+w);
				if (o == UT64_MAX) {
					ut64 o = r_io_section_vaddr_to_maddr_try (io, addr+w);
					if (o == UT64_MAX)
						memset (buf+w, 0xff, l);
				}
				break;
			}
		//} else {
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
		if (len>0) {
			memset (buf+w, 0xff, len);
		}
//break;
	}
	return olen;
=======
	r_io_desc_seek (io->desc, paddr, R_IO_SEEK_SET);
	return io->desc->cbs->read (io, io->desc, buf, len);
>>>>>>> so it begins
}

R_API int r_io_pwrite_at (RIO *io, ut64 paddr, ut8 *buf, int len)
{
	if (!io || !buf || !io->desc || !(io->desc->flags & R_IO_WRITE) || !io->desc->cbs || !io->desc->cbs->write || !len)	//check pointers and permissions
		return 0;
	r_io_desc_seek (io->desc, paddr, R_IO_SEEK_SET);
	return io->desc->cbs->write (io, io->desc, buf, len);
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
// TODO. this is a physical resize
R_API int r_io_resize(RIO *io, ut64 newsize) {
	if (io->plugin) {
		if (io->plugin->resize && io->desc) {
			int res = io->plugin->resize (io, io->desc, newsize);
			if (res)
				r_io_map_truncate_update (io, io->desc->fd, newsize);
			return res;
		}
		return false;
	}
	return true;
}

R_API int r_io_extend(RIO *io, ut64 size) {
	ut64 curr_off = io->off;
	ut64 cur_size = r_io_size (io), tmp_size = cur_size-size;
	ut8 *buffer = NULL;

	if (!size) return false;

	if (io->plugin && io->plugin->extend)
		return io->plugin->extend (io, io->desc, size);

	if (!r_io_resize (io, size+cur_size)) return false;

	if (cur_size < size) {
		tmp_size = size - cur_size;
	}

	buffer = malloc (tmp_size);
	// shift the bytes over by size
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	r_io_read (io, buffer, tmp_size);
	// move/write the bytes
	r_io_seek (io, curr_off+size, R_IO_SEEK_SET);
	r_io_write (io, buffer, tmp_size);
	// zero out new bytes
	if (cur_size < size) {
		free (buffer);
		buffer = malloc (size);
	}
	memset (buffer, 0, size);
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	r_io_write (io, buffer, size);
	// reset the cursor
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	free (buffer);
	return true;
}

R_API int r_io_extend_at(RIO *io, ut64 addr, ut64 size) {
	if (!size) return false;
	r_io_seek (io, addr, R_IO_SEEK_SET);
	return 	r_io_extend (io, size);
}

R_API int r_io_set_write_mask(RIO *io, const ut8 *buf, int len) {
	int ret = false;
	if (len>0) {
		io->write_mask_fd = io->desc->fd;
		io->write_mask_buf = (ut8 *)malloc (len);
		memcpy (io->write_mask_buf, buf, len);
		io->write_mask_len = len;
		ret = true;
	} else io->write_mask_fd = -1;
	return ret;
}

R_API int r_io_write(RIO *io, const ut8 *buf, int len) {
	int i, ret = -1;
	ut8 *data = NULL;

	/* check section permissions */
	if (io->enforce_rwx & R_IO_WRITE)
		if (!(r_io_section_get_rwx (io, io->off) & R_IO_WRITE))
			return -1;

	if (io->cached) {
		ret = r_io_cache_write (io, io->off, buf, len);
		if (ret == len)
			return len;
		if (ret > 0) {
			len -= ret;
			buf += ret;
		}
	}

	/* TODO: implement IO cache here. to avoid dupping work on vm for example */

	/* apply write binary mask */
	if (io->write_mask_fd != -1) {
		data = malloc (len);
		r_io_seek (io, io->off, R_IO_SEEK_SET);
		r_io_read (io, data, len);
		r_io_seek (io, io->off, R_IO_SEEK_SET);
		for (i=0; i<len; i++)
			data[i] = buf[i] & \
				io->write_mask_buf[i%io->write_mask_len];
		buf = data;
	}

	// this makes a double sub, so we restore the io->off
	{
		ut64 addr = io->off;
		r_io_map_select (io, io->off);
		io->off = addr;
	}

	if (io->plugin) {
		if (io->plugin->write) {
			ret = io->plugin->write (io, io->desc, buf, len);
		} else { 
			eprintf ("r_io_write: io handler with no write callback\n");
			ret = -1;
		}
	} else {
		if (io->desc) {
			ret = write (io->desc->fd, buf, len);
		} else ret = -1;
	}
	if (ret == -1) {
		if (io->cached != 2) {
			eprintf ("r_io_write: cannot write on fd %d\n",
				io->desc? io->desc->fd: -1);
			r_io_cache_invalidate (io, io->off, io->off+1);
		}
	} else {
		if (io->desc) {
			r_io_map_write_update (io, io->desc->fd, io->off, ret);
			io->off += ret;
		}
	}
	free (data);
	return ret;
=======
R_API int r_io_vread_at (RIO *io, ut64 vaddr, ut8 *buf, int len)
{
	if (!io || !buf)
		return R_FALSE;
	if (!len)
		return R_TRUE;
	r_io_map_cleanup (io);
	if (!io->maps)
		return r_io_pread_at (io, vaddr, buf, len);
	operate_on_itermap (io->maps->tail, io, vaddr, buf, len, R_IO_READ, r_io_pread_at);
	return R_TRUE;
}

R_API int r_io_vwrite_at (RIO *io, ut64 vaddr, ut8 *buf, int len)
{
	if (!io || !buf)
		return R_FALSE;
	if (!len)
		return R_TRUE;
	r_io_map_cleanup (io);
	if (!io->maps)
		return r_io_pwrite_at (io, vaddr, buf, len);
	operate_on_itermap (io->maps->tail, io, vaddr, buf, len, R_IO_WRITE, r_io_pwrite_at);
	return R_TRUE;
}

R_API int r_io_read_at (RIO *io, ut64 addr, ut8 *buf, int len)
{
	if (!io || !buf || !len)
		return 0;
	if (io->va)
		return r_io_vread_at (io, addr, buf, len);
	return r_io_pread_at (io, addr, buf, len);
>>>>>>> so it begins
}

R_API int r_io_write_at (RIO *io, ut64 addr, ut8 *buf, int len)
{
	if (!io || !buf || !len)
		return 0;
	if (io->va)
		return r_io_vwrite_at (io, addr, buf, len);
	return r_io_pwrite_at (io, addr, buf, len);
}

<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence) {
	// TODO: review the offset/vaddr/paddr/maddr thing here
	// now, io-seek always works with vaddr, because it depends on read/write ops that use it
	int posix_whence = SEEK_SET;
	ut64 ret = UT64_MAX;
	if (io == NULL)
		return ret;
	if (io->buffer_enabled) {
		io->off = offset;
		return offset;
	}
	switch (whence) {
	case R_IO_SEEK_SET:
		posix_whence = SEEK_SET;
		ret = offset;
		break;
	case R_IO_SEEK_CUR:
//		offset += io->off;
		posix_whence = SEEK_CUR;
		ret = offset + io->off;
		break;
	case R_IO_SEEK_END:
		//offset = UT64_MAX; // XXX: depending on io bits?
		ret = UT64_MAX;
		posix_whence = SEEK_END;
		break;
	}
	// XXX: list_empty trick must be done in r_io_set_va();
	//eprintf ("-(seek)-> 0x%08llx\n", offset);
	//if (!io->debug && io->va && !r_list_empty (io->sections)) {
	if (!io->debug || !io->raw) { //
		if (io->va && !r_list_empty (io->sections)) {
			ut64 o = r_io_section_vaddr_to_maddr_try (io, offset);
			if (o != UT64_MAX)
				offset = o;
			//	eprintf ("-(vadd)-> 0x%08llx\n", offset);
		}
	}
	// if resolution fails... just return as invalid address
	if (offset==UT64_MAX)
		return UT64_MAX;
	if (io->desc != NULL) {
		if (io->plugin && io->plugin->lseek)
			ret = io->plugin->lseek (io, io->desc, offset, whence);
		// XXX can be problematic on w32..so no 64 bit offset?
		else ret = (ut64)lseek (io->desc->fd, offset, posix_whence);
		if (ret != UT64_MAX) {
			if (whence == R_IO_SEEK_SET)
				io->off = offset; // FIX linux-arm-32-bs at 0x10000
			else io->off = ret;
			// XXX this can be tricky.. better not to use this .. must be deprecated
			// r_io_sundo_push (io);
			ret = (!io->debug && io->va && !r_list_empty (io->sections))?
				r_io_section_maddr_to_vaddr (io, io->off) : io->off;
		} //else eprintf ("r_io_seek: cannot seek to %"PFMT64x"\n", offset);
	} //else { eprintf ("r_io_seek: null fd\n"); }
	return ret;
=======
//remove all descs and maps
R_API int r_io_fini (RIO *io)
{
	if (!io)
		return R_FALSE;
	r_io_desc_fini (io);
	r_io_map_fini (io);
	return R_TRUE;
>>>>>>> so it begins
}

R_API void r_io_free (RIO *io)
{
	r_io_fini (io);
	free (io);
}

//not public api
void operate_on_itermap (SdbListIter *iter, RIO *io, ut64 vaddr, ut8 *buf, int len, int match_flg, int (op (RIO *io, ut64 addr, ut8 *buf, int len)))
{
	RIODesc *temp;
	RIOMap *map;
	ut64 vendaddr;
	if (!io || !len || !buf)
		return;
	if (!iter) {
		op (io, vaddr, buf, len);				//end of list
		return;
	}
	if ((UT64_MAX - len + 1) < vaddr) {				//this block is not that much elegant
		int nlen;						//needed for edge-cases
		vendaddr = UT64_MAX;					//add a test for this block
		nlen = (int)(vendaddr - vaddr + 1);
		operate_on_itermap (iter, io, 0LL, buf + nlen, len - nlen, match_flg, op);
	} else	vendaddr = vaddr + len - 1;
	map = (RIOMap *)iter->data;
	while (!r_io_map_is_in_range (map, vaddr, vendaddr)) {		//search for next map or end of list
		iter = iter->p;
		if (!iter) {						//end of list
			op (io, vaddr, buf, len);			//pread/pwrite
			return;
		}
		map = (RIOMap *)iter->data;
	}
	if (map->from >= vaddr) {
		operate_on_itermap (iter->p, io, vaddr, buf, (int)(map->from - vaddr), match_flg, op);
		buf = buf + (map->from - vaddr);
		vaddr = map->from;
		len = (int)(vendaddr - vaddr + 1);
		if (vendaddr <= map->to) {
			if ((map->flags & match_flg) == match_flg) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta, buf, len);
				io->desc = temp;
			}
		} else {
			if ((map->flags & match_flg) == match_flg) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta, buf, len - (int)(vendaddr - map->to));
				io->desc = temp;
			}
			vaddr = map->to + 1;
			buf = buf + (len - (int)(vendaddr - map->to));
			len = (int)(vendaddr - map->to);
			operate_on_itermap (iter->p, io, vaddr, buf, len, match_flg, op);
		}
<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
	}
#endif
	return 0;
}

R_API ut64 r_io_size(RIO *io) {
	int oldva;
	ut64 size, here;
	if (!io) return 0LL;
	oldva = io->va;
	if (r_io_is_listener (io))
		return UT64_MAX;
	io->va = false;
	here = r_io_seek (io, 0, R_IO_SEEK_CUR);
	size = r_io_seek (io, 0, R_IO_SEEK_END);
	if (r_io_seek (io, here, R_IO_SEEK_SET) != here) {
		eprintf("Failed to reset the file position\n");
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
	if (io->plugin && io->plugin->system)
		ret = io->plugin->system (io, io->desc, cmd);
	return ret;
}

R_API int r_io_close(RIO *io, RIODesc *d) {
	RIODesc *cur = NULL;
	if (io == NULL || d == NULL)
		return -1;
	if (d != io->desc)
		cur = io->desc;
	if (r_io_use_desc (io, d)) {
		int nfd = d->fd;
		RIODesc *desc = r_io_desc_get (io, nfd);
		if (desc) {
			if (desc == io->desc) {
				cur = NULL;
=======
	} else {
		if (vendaddr <= map->to) {
			if ((map->flags & match_flg) == match_flg) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta + (vaddr - map->from), buf, len);		//warning: may overflow in rare usecases
				io->desc = temp;
>>>>>>> so it begins
			}
		} else {
			if ((map->flags & match_flg) == match_flg) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta + (vaddr - map->from), buf, len - (int)(vendaddr - map->to));
				io->desc = temp;
			}
<<<<<<< 5d874bc8d5dd55cf4b06ac56757002cb0e54163a
			r_io_desc_del (io, desc->fd);
		}
	}
	io->desc = cur;
	return false;
}

R_API int r_io_close_all (RIO *io) {
	// LOT OF MEMLEAKS HERE
	if (!io) return 0;
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
	if (r_io_is_listener (io) && io->plugin && io->plugin->accept)
		return io->plugin->accept (io, io->desc, fd);
	return false;
}

/* moves bytes up (+) or down (-) within the specified range */
R_API int r_io_shift(RIO *io, ut64 start, ut64 end, st64 move) {
	ut8 *buf;
	ut64 chunksize = 0x10000;
	ut64 rest, src, shiftsize = r_num_abs (move);
	if (!shiftsize || (end-start) <= shiftsize) return false;
	rest = (end-start) - shiftsize;

	if (!(buf = malloc (chunksize))) return false;

	if (move>0) src = end-shiftsize;
	else src = start+shiftsize;

	while (rest>0) {
		if (chunksize>rest) chunksize=rest;
		if (move>0) src -= chunksize;

		r_io_read_at (io, src, buf, chunksize);
		r_io_write_at (io, src+move, buf, chunksize);

		if (move<0) src += chunksize;
		rest -= chunksize;
	}
	free (buf);
	return true;
}

R_API int r_io_create (RIO *io, const char *file, int mode, int type) {
	if (io->plugin && io->plugin->create)
		return io->plugin->create (io, file, mode, type);
	if (type == 'd'|| type == 1)
		return r_sys_mkdir (file);
	return r_sandbox_creat (file, mode)? false: true;
}

R_API void r_io_sort_maps (RIO *io) {
	r_list_sort (io->maps, (RListComparator) r_io_map_sort);
}

// THIS IS pread.. a weird one
static ut8 * r_io_desc_read (RIO *io, RIODesc * desc, ut64 *out_sz) {
	ut8 *buf = NULL;
	ut64 off = 0;

	if (!io || !desc || !out_sz) {
		return NULL;
	}

	if (*out_sz == UT64_MAX)
		*out_sz = r_io_desc_size (io, desc);
	if (*out_sz == 0x8000000) {
		*out_sz = 1024 * 1024 * 1; // 2MB
	}
	off = io->off;

	if (*out_sz == UT64_MAX) return buf;
	if (*out_sz > R_IO_MAX_ALLOC) {
		return buf;
	}

	buf = malloc (*out_sz);
	if (!buf) {
		eprintf ("Cannot allocate %"PFMT64d" bytes\n", *out_sz);
		return NULL;
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

static RIO * r_io_bind_get_io(RIOBind *bnd) {
	return bnd ? bnd->io : NULL;
}

R_API void r_io_set_raw(RIO *io, int raw) {
	io->raw = raw?1:0;
}

// check if reading at offset or writting to offset is reasonable
R_API int r_io_is_valid_offset (RIO *io, ut64 offset, int hasperm) {
	if (!io) {
		eprintf ("r_io_is_valid_offset: io is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
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
if (!ret)
	r_sys_backtrace ();
}
#endif
	switch (io->va) {
#if 0
       case 0: return (offset < r_io_size (io));
       case 1: return (r_io_map_exists_for_offset (io, offset) ||
                       r_io_section_exists_for_vaddr (io, offset, hasperm));
#else
	case 0:
	       {
		       if ((r_io_map_exists_for_offset (io, offset))) {
			       return true;
		       }
		       return (offset < r_io_size (io));
	       }
	       break;
	case 1:
	       if (io->debug) {
			// check debug maps here
			return 1;
	       } else {
		       if (io->sectonly) {
			       if (r_list_empty (io->sections)) {
				       return true;
			       }
			       return (r_io_map_exists_for_offset (io, offset) ||
					       r_io_section_exists_for_vaddr (io, offset, hasperm));
		       } else {
			       return (r_io_map_exists_for_offset (io, offset) ||
					       r_io_section_exists_for_vaddr (io, offset, hasperm));
			       //return (offset < r_io_size (io));
		       }
	       }
#endif
	} // more io.va modes pls
	eprintf ("r_io_is_valid_offset: io->va is %i\n", io->va);
	r_sys_backtrace ();
	return R_FAIL;
=======
			vaddr = map->to + 1;
			buf = buf + (len - (int)(vendaddr - map->to));
			len = (int)(vendaddr - map->to);
			operate_on_itermap (iter->p, io, vaddr, buf, len, match_flg, op);
		}
	}
>>>>>>> so it begins
}
