/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_io.h>
#include <r_util.h>
#include <r_cons.h>
// TODO: to be deprecated.. this is slow and boring

R_API void r_io_desc_init(RIO *io) {
	io->files = r_list_new ();
	if (!io->files) return;
	io->files->free = (RListFree)r_io_desc_free;
}

R_API void r_io_desc_fini(RIO *io) {
	r_list_free (io->files);
}

R_API ut64 r_io_desc_size(RIO *io, RIODesc *desc){
	RIODesc *old = NULL;
	ut64 sz = -1;
	if (desc && io->desc != desc){
		old = io->desc;
		r_io_use_desc (io, desc);
	}
	if (desc) {
		sz = r_io_size (io);
	}
	if (old) {
		r_io_use_desc (io, old);
	}
	return sz;
}

R_API RIODesc *r_io_desc_new(RIOPlugin *plugin, int fd, const char *name, int flags, int mode, void *data) {
	RETURN_IO_DESC_NEW (plugin, fd, name, flags, mode, data);
}
#if 0
	int i;
	RIODesc *desc = R_NEW (RIODesc);
	if (!desc) return NULL;
	if (fd==-1) eprintf ("WARNING: r_io_desc_new with fd = -1\n");
	desc->state = R_IO_DESC_TYPE_OPENED;
	desc->name = strdup (name);
	if (!desc->name) {
		free (desc);
		return NULL;
	}
	desc->plugin = plugin;
	desc->flags = flags;
	if (fd == -2) {
		ut8 *p = (ut8 *)&(desc->fd);
		desc->fd = ((int) ((size_t) desc) & 0xffffff);
		desc->fd = p[0];
		for (i=1; i<sizeof (desc->fd); i++)
			desc->fd ^= p[i];
	} else desc->fd = fd;
	desc->data = data;
	return desc;
#endif

R_API void r_io_desc_free(RIODesc *desc) {
	if (!desc) {
		return;
	}
	if (desc->io) {
		RIO* io = (RIO*)desc->io;
		desc->io = NULL;
		r_io_close (io, desc);
	}
	if (desc->plugin && desc->plugin->close)
		desc->plugin->close (desc);
	R_FREE (desc->name);
	R_FREE (desc->uri);
	R_FREE (desc->referer);
	free (desc);
}

R_API int r_io_desc_add(RIO *io, RIODesc *desc) {
	RIODesc *foo = r_io_desc_get (io, desc->fd);
	if (!foo){
		desc->io = io;
		r_list_append (io->files, desc);
	}
	return foo? 1: 0;
}

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
}

R_API RIODesc *r_io_desc_get(RIO *io, int fd) {
	RListIter *iter;
	RIODesc *d;
	if (fd<0)
		return NULL;
	r_list_foreach (io->files, iter, d) {
		if (d && d->fd == fd)
			return d;
	}
	return NULL;
}

R_API ut64 r_io_desc_seek (RIO *io, RIODesc *desc, ut64 offset) {
	if (!io || !desc)
		return UT64_MAX;
	if (!desc->plugin)
		return (ut64)lseek (desc->fd, offset, SEEK_SET);
	return desc->plugin->lseek (io, desc, offset, SEEK_SET);
}

R_API void r_io_desc_list (RIO *io) {
	RIODesc *desc = NULL;
	RListIter *iter;
	if (io && io->files) {
		r_list_foreach (io->files, iter, desc) {
			if (desc) {
				io->cb_printf ("- %i", desc->fd);
				if (desc->uri)
					io->cb_printf ("\t%s", desc->uri);
				if (desc->name)
					io->cb_printf ("\t%s", desc->name);
				io->cb_printf ("\tstate: %i\tflags: %s\n", desc->state, r_str_rwx_i (desc->flags));
			}
		}
	}
}

#if 0
// XXX: This must be deprecated in order to promote the cast of dataptr to ut32
R_API int r_io_desc_generate(struct r_io_t *io) {
	int fd;
	do fd = 0xf000 + rand ()%0xfff;
	while (r_io_desc_get(io, fd));
	return fd;
}
#endif

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
		if (min == -1 || s->from < min) {
			min = s->from;
		}
		if (max == -1 || s->to > max) {
			max = s->to;
		}
	}
	mul = (max-min) / width;
	if (min != -1 && mul != 0) {
		const char * color = "", *color_end = "";
		i = 0;
		r_list_foreach (io->maps, iter, s) {
			if (use_color) {
				color_end = Color_RESET;
				if (s->flags & 1) { // exec bit
					color = Color_GREEN;
				} else if (s->flags & 2) { // write bit
					color = Color_RED;
				} else {
					color = "";
					color_end = "";
				}
			} else {
				color = "";
				color_end = "";
			}
			if (io->va) {
				io->cb_printf ("%02d%c %s0x%08"PFMT64x"%s |", i,
						(seek>=s->from&& seek<s->to)?'*':' ',
						//(seek>=s->vaddr && seek<s->vaddr+s->size)?'*':' ',
						color, s->from, color_end);
			} else {
				io->cb_printf ("%02d%c %s0x%08"PFMT64x"%s |", i,
						(seek >= s->from && seek < s->to) ? '*':' ',
						color, s->from, color_end);
			}
			for (j=0; j<width; j++) {
				ut64 pos = min + (j*mul);
				ut64 npos = min + ((j+1)*mul);
				if (s->from<npos && (s->to)>pos)
					io->cb_printf ("#");
				else io->cb_printf ("-");
			}
			io->cb_printf ("| %s0x%08"PFMT64x"%s %s %d\n",
				color, s->to, color_end,
				r_str_rwx_i (s->flags), s->fd);
			i++;
		}
		/* current seek */
		if (i>0 && len != 0) {
			if (seek == UT64_MAX)
				seek = 0;
			//len = 8096;//r_io_size (io);
			io->cb_printf ("=>  0x%08"PFMT64x" |", seek);
			for (j=0;j<width;j++) {
				io->cb_printf (
					((j*mul)+min >= seek &&
					 (j*mul)+min <= seek+len)
					?"^":"-");
			}
			io->cb_printf ("| 0x%08"PFMT64x"\n", seek+len);
		}
	}
}

R_API bool r_io_desc_detach (RIO *io, RIODesc *fd) {
	bool ret = false;
	RIODesc *d, *prev = NULL;
	RListIter *iter;
	void *p = io->files->free;
	r_list_foreach (io->files, iter, d) {
		if (d == fd) {
			io->files->free = NULL;
			r_list_delete (io->files, iter);
			ret = true;
		}
		if (!prev) {
			prev = d;
		}
		if (ret && prev) {
			break;
		}
	}
	io->files->free = p;
	r_io_raise (io, prev->fd);
	return ret;
}
