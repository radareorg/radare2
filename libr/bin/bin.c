/* radare2 - LGPL - Copyright 2009-2018 - pancake, nibble, dso */

#include <r_bin.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_io.h>
#include <config.h>

R_LIB_VERSION (r_bin);

#define DB a->sdb;
#define RBINLISTFREE(x)\
	if (x) { \
		r_list_free (x);\
		x = NULL;\
	}

#define ARCHS_KEY "archs"

#if !defined(R_BIN_STATIC_PLUGINS)
#define R_BIN_STATIC_PLUGINS 0
#endif
#if !defined(R_BIN_XTR_STATIC_PLUGINS)
#define R_BIN_XTR_STATIC_PLUGINS 0
#endif
#if !defined(R_BIN_LDR_STATIC_PLUGINS)
#define R_BIN_LDR_STATIC_PLUGINS 0
#endif

static RBinPlugin *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS, NULL };
static RBinXtrPlugin *bin_xtr_static_plugins[] = { R_BIN_XTR_STATIC_PLUGINS, NULL };
static RBinLdrPlugin *bin_ldr_static_plugins[] = { R_BIN_LDR_STATIC_PLUGINS, NULL };

static bool r_bin_load_io_at_offset_as(RBin *bin, int fd, ut64 baseaddr, ut64 loadaddr, int xtr_idx, ut64 offset, const char *name);

static int getoffset(RBin *bin, int type, int idx) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (plugin && plugin->get_offset) {
		return plugin->get_offset (a, type, idx);
	}
	return -1;
}

static const char *getname(RBin *bin, int type, int idx) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (plugin && plugin->get_name) {
		return plugin->get_name (a, type, idx);
	}
	return NULL;
}

static ut64 binobj_a2b(RBinObject *o, ut64 addr) {
	return addr + (o? o->baddr_shift: 0);
}

R_API void r_bin_iobind(RBin *bin, RIO *io) {
	r_io_bind (io, &bin->iob);
}

// TODO: move these two function do a different file
R_API RBinXtrData *r_bin_xtrdata_new(RBuffer *buf, ut64 offset, ut64 size,
				      ut32 file_count,
				      RBinXtrMetadata *metadata) {
	RBinXtrData *data = R_NEW0 (RBinXtrData);
	if (!data) {
		return NULL;
	}
	data->offset = offset;
	data->size = size;
	data->file_count = file_count;
	data->metadata = metadata;
	data->loaded = 0;
	// TODO: USE RBuffer *buf inside RBinXtrData*
	data->buffer = malloc (size + 1);
	// data->laddr = 0; /// XXX
	if (!data->buffer) {
		free (data);
		return NULL;
	}
	// XXX unnecessary memcpy, this is slow
	memcpy (data->buffer, r_buf_buffer (buf), size);
	data->buffer[size] = 0;
	return data;
}

R_API const char *r_bin_string_type (int type) {
	switch (type) {
	case 'a': return "ascii";
	case 'u': return "utf8";
	case 'w': return "utf16le";
	case 'W': return "utf32le";
	case 'b': return "base64";
	}
	return "ascii"; // XXX
}

R_API void r_bin_xtrdata_free(void /*RBinXtrData*/ *data_) {
	RBinXtrData *data = data_;
	if (data) {
		if (data->metadata) {
			free (data->metadata->libname);
			free (data->metadata->arch);
			free (data->metadata->machine);
			free (data->metadata);
		}
		free (data->file);
		free (data->buffer);
		free (data);
	}
}

R_API RList* r_bin_raw_strings(RBinFile *bf, int min) {
	RList *l = NULL;
	if (bf) {
		int tmp = bf->rawstr;
		bf->rawstr = 2;
		l = r_bin_file_get_strings (bf, min, 0);
		bf->rawstr = tmp;
	}
	return l;
}

R_API int r_bin_dump_strings(RBinFile *a, int min) {
	r_bin_file_get_strings (a, min, 1);
	return 0;
}

/* This is very slow if there are lot of symbols */
R_API int r_bin_load_languages(RBinFile *binfile) {
	if (r_bin_lang_rust (binfile)) {
		return R_BIN_NM_RUST;
	}
	if (r_bin_lang_swift (binfile)) {
		return R_BIN_NM_SWIFT;
	}
	if (r_bin_lang_objc (binfile)) {
		return R_BIN_NM_OBJC;
	}
	if (r_bin_lang_cxx (binfile)) {
		return R_BIN_NM_CXX;
	}
	if (r_bin_lang_dlang (binfile)) {
		return R_BIN_NM_DLANG;
	}
	if (r_bin_lang_msvc (binfile)) {
		return R_BIN_NM_MSVC;
	}
	return R_BIN_NM_NONE;
}

R_API void r_bin_info_free(RBinInfo *rb) {
	if (!rb) {
		return;
	}
	free (rb->intrp);
	free (rb->file);
	free (rb->type);
	free (rb->bclass);
	free (rb->rclass);
	free (rb->arch);
	free (rb->cpu);
	free (rb->machine);
	free (rb->os);
	free (rb->subsystem);
	free (rb->rpath);
	free (rb->guid);
	free (rb->debug_file_name);
	free (rb);
}

R_API void r_bin_import_free(void *_imp) {
	RBinImport *imp = (RBinImport *)_imp;
	if (imp) {
		R_FREE (imp->name);
		R_FREE (imp->classname);
		R_FREE (imp->descriptor);
		free (imp);
	}
}

R_API void r_bin_symbol_free(void *_sym) {
	RBinSymbol *sym = (RBinSymbol *)_sym;
	free (sym->name);
	free (sym->classname);
	free (sym);
}

R_API void r_bin_string_free(void *_str) {
	RBinString *str = (RBinString *)_str;
	free (str->string);
	free (str);
}

// XXX - change this to RBinObject instead of RBinFile
// makes no sense to pass in a binfile and set the RBinObject
// kinda a clunky functions
// XXX - this is a rather hacky way to do things, there may need to be a better
// way.
R_API int r_bin_load(RBin *bin, const char *file, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd, int rawstr) {
	if (!bin) {
		return false;
	}
	// ALIAS?	return r_bin_load_as (bin, file, baseaddr, loadaddr,
	// xtr_idx, fd, rawstr, 0, file);
	RIOBind *iob = &(bin->iob);
	if (!iob) {
		return false;
	}
	if (!iob->io) {
		iob->io = r_io_new ();	//wtf
		if (!iob->io) {
			return false;
		}
		bin->io_owned = true;
		r_io_bind (iob->io, &bin->iob);		//memleak?
		iob = &bin->iob;
	}
	if (!iob->desc_get (iob->io, fd)) {
		fd = iob->fd_open (iob->io, file, R_IO_READ, 0644);
	}
	bin->rawstr = rawstr;
	// Use the current RIODesc otherwise r_io_map_select can swap them later on
	if (fd < 0) {
		if (bin->io_owned) {
			r_io_free (iob->io);
			memset (&bin->iob, 0, sizeof (bin->iob));
			bin->io_owned = false;
		}
		return false;
	}
	//Use the current RIODesc otherwise r_io_map_select can swap them later on
	return r_bin_load_io (bin, fd, baseaddr, loadaddr, xtr_idx);
}

R_API int r_bin_load_as(RBin *bin, const char *file, ut64 baseaddr,
			 ut64 loadaddr, int xtr_idx, int fd, int rawstr,
			 int fileoffset, const char *name) {
	RIOBind *iob = &(bin->iob);
	if (!iob || !iob->io) {
		return false;
	}
	if (fd < 0) {
		fd = iob->fd_open (iob->io, file, R_IO_READ, 0644);
	}
	if (fd < 0) {
		return false;
	}
	return r_bin_load_io_at_offset_as (bin, fd, baseaddr, loadaddr,
						  xtr_idx, fileoffset, name);
}

R_API int r_bin_reload(RBin *bin, int fd, ut64 baseaddr) {
	RIOBind *iob = &(bin->iob);
	RList *the_obj_list = NULL;
	int res = false;
	RBinFile *bf = NULL;
	ut8 *buf_bytes = NULL;
	ut64 sz = UT64_MAX;

	if (!iob || !iob->io) {
		res = false;
		goto error;
	}
	const char *name = iob->fd_get_name (iob->io, fd);
	bf = r_bin_file_find_by_name (bin, name);
	if (!bf) {
		res = false;
		goto error;
	}

	the_obj_list = bf->objs;

	bf->objs = r_list_newf ((RListFree)r_bin_object_free);
	// invalidate current object reference
	bf->o = NULL;

	sz = iob->fd_size (iob->io, fd);
	if (sz == UT64_MAX) { // || sz > (64 * 1024 * 1024)) {
		// too big, probably wrong
		eprintf ("Too big\n");
		res = false;
		goto error;
	}
// TODO: deprecate, the code in the else should be enough
#if 1
	if (sz == UT64_MAX && iob->fd_is_dbg (iob->io, fd)) {
		// attempt a local open and read
		// This happens when a plugin like debugger does not have a
		// fixed size.
		// if there is no fixed size or its MAXED, there is no way to
		// definitively
		// load the bin-properly.  Many of the plugins require all
		// content and are not
		// stream based loaders
		int tfd = iob->fd_open (iob->io, name, R_IO_READ, 0);
		if (tfd < 0) {
			res = false;
			goto error;
		}
		sz = iob->fd_size (iob->io, tfd);
		if (sz == UT64_MAX) {
			iob->fd_close (iob->io, tfd);
			res = false;
			goto error;
		}
		// OMG NOES we want to use io, not this shit. 
		buf_bytes = calloc (1, sz + 1);
		if (!buf_bytes) {
			iob->fd_close (iob->io, tfd);
			res = false;
			goto error;
		}
		if (!iob->read_at (iob->io, 0LL, buf_bytes, sz)) {
			free (buf_bytes);
			iob->fd_close (iob->io, tfd);
			res = false;
			goto error;
		}
		iob->fd_close (iob->io, tfd);
	} else {
		buf_bytes = calloc (1, sz + 1);
		if (!buf_bytes) {
			res = false;
			goto error;
		}
		if (!iob->fd_read_at (iob->io, fd, 0LL, buf_bytes, sz)) {
			free (buf_bytes);
			res = false;
			goto error;
		}
	}
	bool yes_plz_steal_ptr = true;
	r_bin_file_set_bytes (bf, buf_bytes, sz, yes_plz_steal_ptr);
#else
	bf->buf = r_buf_new_with_io (iob, fd);
#endif

	if (r_list_length (the_obj_list) == 1) {
		RBinObject *old_o = (RBinObject *)r_list_get_n (the_obj_list, 0);
		res = r_bin_load_io_at_offset_as (bin, fd, baseaddr,
						old_o->loadaddr, 0, old_o->boffset, NULL);
	} else {
		RListIter *iter = NULL;
		RBinObject *old_o;
		r_list_foreach (the_obj_list, iter, old_o) {
			// XXX - naive. do we need a way to prevent multiple "anys" from being opened?
			res = r_bin_load_io_at_offset_as (bin, fd, baseaddr,
				old_o->loadaddr, 0, old_o->boffset, old_o->plugin->name);
		}
	}
	bf->o = r_list_get_n (bf->objs, 0);

error:
	r_list_free (the_obj_list);

	return res;
}

R_API int r_bin_load_io(RBin *bin, int fd, ut64 baseaddr, ut64 loadaddr, int xtr_idx) {
	return r_bin_load_io_at_offset_as (bin, fd, baseaddr, loadaddr, xtr_idx, 0, NULL);
}

R_API int r_bin_load_io_at_offset_as_sz(RBin *bin, int fd, ut64 baseaddr,
		ut64 loadaddr, int xtr_idx, ut64 offset, const char *name, ut64 sz) {
	RIOBind *iob = &(bin->iob);
	RIO *io = iob? iob->io: NULL;
	RListIter *it;
	ut8 *buf_bytes = NULL;
	RBinXtrPlugin *xtr;
	ut64 file_sz = UT64_MAX;
	RBinFile *binfile = NULL;
	int tfd = -1;

	if (!io || (fd < 0) || (st64)sz < 0) {
		return false;
	}
	bool is_debugger = iob->fd_is_dbg (io, fd);
	const char *fname = iob->fd_get_name (io, fd);
	if (loadaddr == UT64_MAX) {
		loadaddr = 0;
	}
	file_sz = iob->fd_size (io, fd);
	// file_sz = UT64_MAX happens when attaching to frida:// and other non-debugger io plugins which results in double opening
	if (is_debugger && file_sz == UT64_MAX) {
		tfd = iob->fd_open (io, fname, R_IO_READ, 0644);
		if (tfd >= 1) {
			file_sz = iob->fd_size (io, tfd);
		}
	}
	if (!sz) {
		sz = file_sz;
	}
	// check if blockdevice?
	if (sz >= UT32_MAX) {
		sz = 1024 * 32;
	}

	bin->file = fname;
	sz = R_MIN (file_sz, sz);
	if (!r_list_length (bin->binfiles)) {
		if (is_debugger) {
			//use the temporal RIODesc to read the content of the file instead
			//from the memory
			if (tfd >= 0) {
				buf_bytes = calloc (1, sz + 1);
				iob->fd_read_at (io, tfd, 0, buf_bytes, sz);
				// iob->fd_close (io, tfd);
			}
		}
	}
#if 0
	if (!buf_bytes) {
		if (sz < 1) {
			eprintf ("Cannot allocate %d bytes\n", sz + 1);
			return false;
		}
		buf_bytes = calloc (1, sz + 1);
		if (!buf_bytes) {
			eprintf ("Cannot allocate %d bytes.\n", sz + 1);
			return false;
		}
		ut64 seekaddr = is_debugger? baseaddr: loadaddr;
		if (!iob->fd_read_at (io, fd, seekaddr, buf_bytes, sz)) {
			sz = 0LL;
		}
	}
#else
	// this thing works for 2GB ELF core from vbox
	if (!buf_bytes) {
		if (sz < 1) {
			eprintf ("Cannot allocate %d bytes\n", (int)(sz));
			return false;
		}
		buf_bytes = calloc (1, sz);
		if (!buf_bytes) {
			eprintf ("Cannot allocate %d bytes.\n", (int)(sz + 1));
			return false;
		}
		ut64 seekaddr = is_debugger? baseaddr: loadaddr;
		if (!iob->fd_read_at (io, fd, seekaddr, buf_bytes, sz)) {
			sz = 0LL;
		}
	}
#endif
	if (bin->use_xtr && !name && (st64)sz > 0) {
		// XXX - for the time being this is fine, but we may want to
		// change the name to something like
		// <xtr_name>:<bin_type_name>
		r_list_foreach (bin->binxtrs, it, xtr) {
			if (xtr && xtr->check_bytes (buf_bytes, sz)) {
				if (xtr && (xtr->extract_from_bytes || xtr->extractall_from_bytes)) {
					if (is_debugger && sz != file_sz) {
						R_FREE (buf_bytes);
						if (tfd < 0) {
							tfd = iob->fd_open (io, fname, R_IO_READ, 0);
						}
						sz = iob->fd_size (io, tfd);
						if (sz != UT64_MAX) {
							buf_bytes = calloc (1, sz + 1);
							if (buf_bytes) {
								(void) iob->fd_read_at (io, tfd, 0, buf_bytes, sz);
							}
						}
						// DOUBLECLOSE UAF : iob->fd_close (io, tfd);
						tfd = -1;	// marking it closed
					} else if (sz != file_sz) {
						(void) iob->read_at (io, 0LL, buf_bytes, sz);
					}
					binfile = r_bin_file_xtr_load_bytes (bin, xtr,
						fname, buf_bytes, sz, file_sz,
						baseaddr, loadaddr, xtr_idx,
						fd, bin->rawstr);
				}
				xtr = NULL;
			}
		}
	}
	if (!binfile) {
		if (true) {
			binfile = r_bin_file_new_from_bytes (
				bin, fname, buf_bytes, sz, file_sz, bin->rawstr,
				baseaddr, loadaddr, fd, name, NULL, offset, true);
		} else {
			binfile = r_bin_file_new_from_fd (bin, tfd, NULL);
		}
	}
	return binfile? r_bin_file_set_cur_binfile (bin, binfile): false;
}

static bool r_bin_load_io_at_offset_as(RBin *bin, int fd, ut64 baseaddr,
		ut64 loadaddr, int xtr_idx, ut64 offset, const char *name) {
	// adding file_sz to help reduce the performance impact on the system
	// in this case the number of bytes read will be limited to 2MB
	// (MIN_LOAD_SIZE)
	// if it fails, the whole file is loaded.
	const ut64 MAX_LOAD_SIZE = 0;  // 0xfffff; //128 * (1 << 10 << 10);
	int res = r_bin_load_io_at_offset_as_sz (bin, fd, baseaddr,
		loadaddr, xtr_idx, offset, name, MAX_LOAD_SIZE);
	if (!res) {
		res = r_bin_load_io_at_offset_as_sz (bin, fd, baseaddr,
			loadaddr, xtr_idx, offset, name, UT64_MAX);
	}
	return res;
}

R_API RBinPlugin *r_bin_get_binplugin_by_name(RBin *bin, const char *name) {
	RBinPlugin *plugin;
	RListIter *it;
	if (bin && name) {
		r_list_foreach (bin->plugins, it, plugin) {
			if (!strcmp (plugin->name, name)) {
				return plugin;
			}
		}
	}
	return NULL;
}

R_API RBinPlugin *r_bin_get_binplugin_by_bytes(RBin *bin, const ut8 *bytes, ut64 sz) {
	RBinPlugin *plugin;
	RListIter *it;
	if (!bin || !bytes) {
		return NULL;
	}
	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->check_bytes && plugin->check_bytes (bytes, sz)) {
			return plugin;
		}
	}
	return NULL;
}

R_API RBinXtrPlugin *r_bin_get_xtrplugin_by_name(RBin *bin, const char *name) {
	RBinXtrPlugin *xtr;
	RListIter *it;
	if (!bin || !name) {
		return NULL;
	}
	// TODO: use a hashtable here
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, name)) {
			return xtr;
		}
		// must be set to null
		xtr = NULL;
	}
	return NULL;
}

R_API RBinPlugin *r_bin_get_binplugin_any(RBin *bin) {
	return r_bin_get_binplugin_by_name (bin, "any");
}

static void r_bin_plugin_free(RBinPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
	R_FREE (p);
}

// rename to r_bin_plugin_add like the rest
R_API bool r_bin_add(RBin *bin, RBinPlugin *foo) {
	RListIter *it;
	RBinPlugin *plugin;
	if (foo->init) {
		foo->init (bin->user);
	}
	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, foo->name)) {
			return false;
		}
	}
	plugin = R_NEW0 (RBinPlugin);
	memcpy (plugin, foo, sizeof (RBinPlugin));
	r_list_append (bin->plugins, plugin);
	return true;
}

R_API bool r_bin_ldr_add(RBin *bin, RBinLdrPlugin *foo) {
	RListIter *it;
	RBinLdrPlugin *ldr;

	if (foo->init) {
		foo->init (bin->user);
	}
	// avoid duplicates
	r_list_foreach (bin->binldrs, it, ldr) {
		if (!strcmp (ldr->name, foo->name)) {
			return false;
		}
	}
	r_list_append (bin->binldrs, foo);
	return true;
}

R_API bool r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo) {
	RListIter *it;
	RBinXtrPlugin *xtr;

	if (foo->init) {
		foo->init (bin->user);
	}
	// avoid duplicates
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, foo->name)) {
			return false;
		}
	}
	r_list_append (bin->binxtrs, foo);
	return true;
}

R_API void *r_bin_free(RBin *bin) {
	if (!bin) {
		return NULL;
	}
	if (bin->io_owned) {
		r_io_free (bin->iob.io);
	}
	bin->file = NULL;
	free (bin->force);
	free (bin->srcdir);
	//r_bin_free_bin_files (bin);
	r_list_free (bin->binfiles);
	r_list_free (bin->binxtrs);
	r_list_free (bin->plugins);
	r_list_free (bin->binldrs);
	sdb_free (bin->sdb);
	r_id_storage_free (bin->ids);
	memset (bin, 0, sizeof (RBin));
	free (bin);
	return NULL;
}

static bool r_bin_print_plugin_details(RBin *bin, RBinPlugin *bp, int json) {
	if (json == 'q') {
		bin->cb_printf ("%s\n", bp->name);
	} else if (json) {
		bin->cb_printf (
			"{\"name\":\"%s\",\"description\":\"%s\","
			"\"license\":\"%s\"}\n",
			bp->name, bp->desc, bp->license? bp->license: "???");
	} else {
		bin->cb_printf ("Name: %s\n", bp->name);
		bin->cb_printf ("Description: %s\n", bp->desc);
		if (bp->license) {
			bin->cb_printf ("License: %s\n", bp->license);
		}
		if (bp->version) {
			bin->cb_printf ("Version: %s\n", bp->version);
		}
		if (bp->author) {
			bin->cb_printf ("Author: %s\n", bp->author);
		}
	}
	return true;
}

static int r_bin_print_xtrplugin_details(RBin *bin, RBinXtrPlugin *bx, int json) {
	if (json == 'q') {
		bin->cb_printf ("%s\n", bx->name);
	} else if (json) {
		bin->cb_printf (
			"{\"name\":\"%s\",\"description\":\"%s\","
			"\"license\":\"%s\"}\n",
			bx->name, bx->desc, bx->license? bx->license: "???");
	} else {
		bin->cb_printf ("Name: %s\n", bx->name);
		bin->cb_printf ("Description: %s\n", bx->desc);
		if (bx->license) {
			bin->cb_printf ("License: %s\n", bx->license);
		}
	}
	return true;
}

R_API int r_bin_list(RBin *bin, int json) {
	RListIter *it;
	RBinPlugin *bp;
	RBinXtrPlugin *bx;
	RBinLdrPlugin *ld;

	if (json == 'q') {
		r_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf ("%s\n", bp->name);
		}
		r_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf ("%s\n", bx->name);
		}
	} else if (json) {
		int i;

		i = 0;
		bin->cb_printf ("{\"bin\":[");
		r_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf (
				"%s{\"name\":\"%s\",\"description\":\"%s\","
				"\"license\":\"%s\"}",
				i? ",": "", bp->name, bp->desc, bp->license? bp->license: "???");
			i++;
		}

		i = 0;
		bin->cb_printf ("],\"xtr\":[");
		r_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf (
				"%s{\"name\":\"%s\",\"description\":\"%s\","
				"\"license\":\"%s\"}",
				i? ",": "", bx->name, bx->desc, bx->license? bx->license: "???");
			i++;
		}

		i = 0;
		bin->cb_printf ("],\"ldr\":[");
		r_list_foreach (bin->binxtrs, it, ld) {
			bin->cb_printf (
				"%s{\"name\":\"%s\",\"description\":\"%s\","
				"\"license\":\"%s\"}",
				i? ",": "", ld->name, ld->desc, ld->license? ld->license: "???");
			i++;
		}
		bin->cb_printf ("]}\n");
	} else {
		r_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf ("bin  %-11s %s (%s) %s %s\n",
				bp->name, bp->desc, bp->license? bp->license: "???",
				bp->version? bp->version: "",
				bp->author? bp->author: "");
		}
		r_list_foreach (bin->binxtrs, it, bx) {
			const char *name = strncmp (bx->name, "xtr.", 4)? bx->name : bx->name + 3;
			bin->cb_printf ("xtr  %-11s %s (%s)\n", name,
				bx->desc, bx->license? bx->license: "???");
		}
		r_list_foreach (bin->binldrs, it, ld) {
			const char *name = strncmp (ld->name, "ldr.", 4)? ld->name : ld->name + 3;
			bin->cb_printf ("ldr  %-11s %s (%s)\n", name,
				ld->desc, ld->license? ld->license: "???");
		}
	}
	return false;
}

R_API int r_bin_list_plugin(RBin *bin, const char* name, int json) {
	RListIter *it;
	RBinPlugin *bp;
	RBinXtrPlugin *bx;

	r_list_foreach (bin->plugins, it, bp) {
		if (!r_str_cmp (name, bp->name, strlen (name))) {
			continue;
		}
		return r_bin_print_plugin_details (bin, bp, json);
	}
	r_list_foreach (bin->binxtrs, it, bx) {
		if (!r_str_cmp (name, bx->name, strlen (name))) {
			continue;
		}
		return r_bin_print_xtrplugin_details (bin, bx, json);
	}

	eprintf ("cannot find plugin %s\n", name);
	return false;
}

/* returns the base address of bin or UT64_MAX in case of errors */
R_API ut64 r_bin_get_baddr(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return r_bin_object_get_baddr (o);
}

/* returns the load address of bin or UT64_MAX in case of errors */
R_API ut64 r_bin_get_laddr(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->loadaddr: UT64_MAX;
}

R_API void r_bin_set_baddr(RBin *bin, ut64 baddr) {
	RBinObject *o = r_bin_cur_object (bin);
	r_bin_object_set_baddr (o, baddr);
	// XXX - update all the infos?
}

R_API ut64 r_bin_get_boffset(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->boffset: UT64_MAX;
}

R_API RBinAddr *r_bin_get_sym(RBin *bin, int sym) {
	RBinObject *o = r_bin_cur_object (bin);
	if (sym < 0 || sym >= R_BIN_SYM_LAST) {
		return NULL;
	}
	return o? o->binsym[sym]: NULL;
}

// XXX: those accessors are redundant
R_API RList *r_bin_get_entries(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->entries: NULL;
}

R_API RList *r_bin_get_fields(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->fields: NULL;
}

R_API RList *r_bin_get_imports(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->imports: NULL;
}

R_API RBinInfo *r_bin_get_info(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->info: NULL;
}

R_API RList *r_bin_get_libs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->libs: NULL;
}

R_API RList * r_bin_patch_relocs(RBin *bin) {
	static bool first = true;
	RBinObject *o = r_bin_cur_object (bin);
	if (!o) {
		return NULL;
	}
	// r_bin_object_set_items set o->relocs but there we don't have access
	// to io
	// so we need to be run from bin_relocs, free the previous reloc and get
	// the patched ones
	if (first && o->plugin && o->plugin->patch_relocs) {
		RList *tmp = o->plugin->patch_relocs (bin);
		first = false;
		if (!tmp) {
			return o->relocs;
		}
		r_list_free (o->relocs);
		o->relocs = tmp;
		REBASE_PADDR (o, o->relocs, RBinReloc);
		first = false;
		return o->relocs;
	}
	return o->relocs;
}

R_API RList *r_bin_get_relocs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->relocs: NULL;
}

R_API RList *r_bin_get_sections(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->sections: NULL;
}

// TODO: Move into section.c and rename it to r_io_section_get_at ()
R_API RBinSection *r_bin_get_section_at(RBinObject *o, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;
	if (o) {
		// TODO: must be O(1) .. use sdb here
		r_list_foreach (o->sections, iter, section) {
			from = va? binobj_a2b (o, section->vaddr): section->paddr;
			to = va? (binobj_a2b (o, section->vaddr) + section->vsize) :
				(section->paddr + section->size);
			if (off >= from && off < to) {
				return section;
			}
		}
	}
	return NULL;
}

R_API RList *r_bin_reset_strings(RBin *bin) {
	RBinFile *a = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);

	if (!a || !o) {
		return NULL;
	}
	if (o->strings) {
		r_list_free (o->strings);
		o->strings = NULL;
	}

	if (bin->minstrlen <= 0) {
		return NULL;
	}
	a->rawstr = bin->rawstr;

	if (plugin && plugin->strings) {
		o->strings = plugin->strings (a);
	} else {
		o->strings = r_bin_file_get_strings (a, bin->minstrlen, 0);
	}
	if (bin->debase64) {
		r_bin_object_filter_strings (o);
	}
	return o->strings;
}

R_API RList *r_bin_get_strings(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->strings: NULL;
}

R_API int r_bin_is_string(RBin *bin, ut64 va) {
	RBinString *string;
	RListIter *iter;
	RList *list;
	if (!(list = r_bin_get_strings (bin))) {
		return false;
	}
	r_list_foreach (list, iter, string) {
		if (string->vaddr == va) {
			return true;
		}
		if (string->vaddr > va) {
			return false;
		}
	}
	return false;
}

//callee must not free the symbol
R_API RBinSymbol *r_bin_get_symbol_at_vaddr(RBin *bin, ut64 addr) {
	//use skiplist here
	RList *symbols = r_bin_get_symbols (bin);
	RListIter *iter;
	RBinSymbol *symbol;
	r_list_foreach (symbols, iter, symbol) {
		if (symbol->vaddr == addr) {
			return symbol;
		}
	}
	return NULL;
}

//callee must not free the symbol
R_API RBinSymbol *r_bin_get_symbol_at_paddr(RBin *bin, ut64 addr) {
	//use skiplist here
	RList *symbols = r_bin_get_symbols (bin);
	RListIter *iter;
	RBinSymbol *symbol;
	r_list_foreach (symbols, iter, symbol) {
		if (symbol->paddr == addr) {
			return symbol;
		}
	}
	return NULL;
}

R_API RList *r_bin_get_symbols(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->symbols: NULL;
}

R_API RList *r_bin_get_mem(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->mem: NULL;
}

R_API int r_bin_is_big_endian(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return (o && o->info)? o->info->big_endian: -1;
}

R_API int r_bin_is_stripped(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_STRIPPED & o->info->dbg_info): 1;
}

R_API int r_bin_is_static(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o && r_list_length (o->libs) > 0)
		return R_BIN_DBG_STATIC & o->info->dbg_info;
	return true;
}

// TODO: Integrate with r_bin_dbg */
R_API int r_bin_has_dbg_linenums(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_LINENUMS & o->info->dbg_info): false;
}

R_API int r_bin_has_dbg_syms(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_SYMS & o->info->dbg_info): false;
}

R_API int r_bin_has_dbg_relocs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_RELOCS & o->info->dbg_info): false;
}

R_API RBin *r_bin_new() {
	int i;
	RBinXtrPlugin *static_xtr_plugin;
	RBinLdrPlugin *static_ldr_plugin;
	RBin *bin = R_NEW0 (RBin);
	if (!bin) {
		return NULL;
	}
	bin->force = NULL;
	bin->filter_rules = UT64_MAX;
	bin->sdb = sdb_new0 ();
	bin->cb_printf = (PrintfCallback)printf;
	bin->plugins = r_list_newf ((RListFree)r_bin_plugin_free);
	bin->minstrlen = 0;
	bin->strpurge = NULL;
	bin->want_dbginfo = true;
	bin->cur = NULL;
	bin->io_owned = false;
	bin->ids = r_id_storage_new (0, ST32_MAX);

	/* bin parsers */
	bin->binfiles = r_list_newf ((RListFree)r_bin_file_free);
	for (i = 0; bin_static_plugins[i]; i++) {
		r_bin_add (bin, bin_static_plugins[i]);
	}
	/* extractors */
	bin->binxtrs = r_list_new ();
	bin->binxtrs->free = free;
	for (i = 0; bin_xtr_static_plugins[i]; i++) {
		static_xtr_plugin = R_NEW0 (RBinXtrPlugin);
		if (!static_xtr_plugin) {
			free (bin);
			return NULL;
		}
		*static_xtr_plugin = *bin_xtr_static_plugins[i];
		r_bin_xtr_add (bin, static_xtr_plugin);
	}
	/* loaders */
	bin->binldrs = r_list_new ();
	bin->binldrs->free = free;
	for (i = 0; bin_ldr_static_plugins[i]; i++) {
		static_ldr_plugin = R_NEW0 (RBinLdrPlugin);
		if (!static_ldr_plugin) {
			free (bin);
			return NULL;
		}
		*static_ldr_plugin = *bin_ldr_static_plugins[i];
		r_bin_ldr_add (bin, static_ldr_plugin);
	}
	return bin;
}

R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits, name);
	RBinObject *obj = NULL;
	if (binfile) {
		obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
		if (!obj) {
			if (binfile->xtr_data) {
				RBinXtrData *xtr_data = r_list_get_n (binfile->xtr_data, 0);
				if (!r_bin_file_object_new_from_xtr_data (bin, binfile,
						UT64_MAX, r_bin_get_laddr (bin), xtr_data)) {
					return false;
				}
				obj = r_list_get_n (binfile->objs, 0);
			}
		}
	} else {
		void *plugin = r_bin_get_binplugin_by_name (bin, name);
		if (plugin) {
			if (bin->cur) {
				bin->cur->curplugin = plugin;
			}
			binfile = r_bin_file_new (bin, "-", NULL, 0, 0, 0, 999, NULL, NULL, false);
			// create object and set arch/bits
			obj = r_bin_object_new (binfile, plugin, 0, 0, 0, 1024);
			binfile->o = obj;
			obj->info = R_NEW0 (RBinInfo);
			obj->info->arch = strdup (arch);
			obj->info->bits = bits;
		}
	}
	return r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API int r_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	RBinFile *cur = r_bin_cur (bin);
	RBinObject *obj = NULL;
	name = !name && cur? cur->file: name;
	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits, name);
	if (binfile && name) {
		obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	}
	return r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API int r_bin_select_object(RBinFile *binfile, const char *arch, int bits, const char *name) {
	RBinObject *obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	return r_bin_file_set_cur_binfile_obj (binfile->rbin, binfile, obj);
}

R_API int r_bin_select_by_ids(RBin *bin, ut32 binfile_id, ut32 binobj_id) {
	RBinFile *binfile = NULL;
	RBinObject *obj = NULL;

	if (binfile_id == UT32_MAX && binobj_id == UT32_MAX) {
		return false;
	}
	if (binfile_id == -1) {
		binfile = r_bin_file_find_by_object_id (bin, binobj_id);
		obj = binfile? r_bin_file_object_find_by_id (binfile, binobj_id): NULL;
	} else if (binobj_id == -1) {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile? binfile->o: NULL;
	} else {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile? r_bin_file_object_find_by_id (binfile, binobj_id): NULL;
	}
	return r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API int r_bin_select_idx(RBin *bin, const char *name, int idx) {
	RBinFile *nbinfile = NULL, *binfile = r_bin_cur (bin);
	RBinObject *obj = NULL;
	const char *tname = !name && binfile? binfile->file: name;
	int res = false;
	if (!tname || !bin) {
		return res;
	}
	nbinfile = r_bin_file_find_by_name_n (bin, tname, idx);
	obj = nbinfile? r_list_get_n (nbinfile->objs, idx): NULL;
	return r_bin_file_set_cur_binfile_obj (bin, nbinfile, obj);
}

static void list_xtr_archs(RBin *bin, int mode) {
	RBinFile *binfile = r_bin_cur (bin);
	if (binfile->xtr_data) {
		RListIter *iter_xtr;
		RBinXtrData *xtr_data;
		int bits, i = 0;
		char *arch, *machine;

		if (mode == 'j') {
			bin->cb_printf ("\"bins\":[");
		}

		r_list_foreach (binfile->xtr_data, iter_xtr, xtr_data) {
			if (!xtr_data || !xtr_data->metadata ||
				!xtr_data->metadata->arch) {
				continue;
			}
			arch = xtr_data->metadata->arch;
			machine = xtr_data->metadata->machine;
			bits = xtr_data->metadata->bits;
			switch (mode) {
			case 'q':
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j':
				bin->cb_printf (
					"%s{\"arch\":\"%s\",\"bits\":%d,"
					"\"offset\":%" PFMT64d
					",\"size\":%" PFMT64d
					",\"machine\":\"%s\"}",
					i++ ? "," : "", arch, bits,
					xtr_data->offset, xtr_data->size,
					machine);
				break;
			default:
				bin->cb_printf ("%03i 0x%08" PFMT64x
						" %" PFMT64d " %s_%i %s\n",
						i++, xtr_data->offset,
						xtr_data->size, arch, bits,
						machine);
				break;
			}
		}

		if (mode == 'j') {
			bin->cb_printf ("]");
		}
	}
}

R_API void r_bin_list_archs(RBin *bin, int mode) {
	RListIter *iter;
	int i = 0;
	char unk[128];
	char archline[128];
	RBinFile *binfile = r_bin_cur (bin);
	RBinObject *obj = NULL;
	const char *name = binfile? binfile->file: NULL;
	int narch = binfile? binfile->narch: 0;

	//are we with xtr format?
	if (binfile && binfile->curxtr) {
		list_xtr_archs (bin, mode);
		return;
	}
	Sdb *binfile_sdb = binfile? binfile->sdb: NULL;
	if (!binfile_sdb) {
		eprintf ("Cannot find SDB!\n");
		return;
	} else if (!binfile) {
		eprintf ("Binary format not currently loaded!\n");
		return;
	}
	sdb_unset (binfile_sdb, ARCHS_KEY, 0);
	if (mode == 'j') {
		bin->cb_printf ("\"bins\":[");
	}
	RBinFile *nbinfile = r_bin_file_find_by_name_n (bin, name, i);
	if (!nbinfile) {
		return;
	}
	i = -1;
	r_list_foreach (nbinfile->objs, iter, obj) {
		RBinInfo *info = obj->info;
		char bits = info? info->bits: 0;
		ut64 boffset = obj->boffset;
		ut32 obj_size = obj->obj_size;
		const char *arch = info? info->arch: NULL;
		const char *machine = info? info->machine: "unknown_machine";

		i++;
		if (!arch) {
			snprintf (unk, sizeof (unk), "unk_%d", i);
			arch = unk;
		}

		if (info && narch > 1) {
			switch (mode) {
			case 'q':
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j':
				bin->cb_printf ("%s{\"arch\":\"%s\",\"bits\":%d,"
						"\"offset\":%" PFMT64d ",\"size\":%d,"
						"\"machine\":\"%s\"}",
						i? ",": "", arch, bits,
						boffset, obj_size, machine);
				break;
			default:
				bin->cb_printf ("%03i 0x%08" PFMT64x " %d %s_%i %s\n", i,
						boffset, obj_size, arch, bits, machine);
			}
			snprintf (archline, sizeof (archline) - 1,
				"0x%08" PFMT64x ":%d:%s:%d:%s",
				boffset, obj_size, arch, bits, machine);
			/// xxx machine not exported?
			//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
		} else {
			if (info) {
				switch (mode) {
				case 'q':
					bin->cb_printf ("%s\n", arch);
					break;
				case 'j':
					bin->cb_printf ("%s{\"arch\":\"%s\",\"bits\":%d,"
							"\"offset\":%" PFMT64d ",\"size\":%d,"
							"\"machine\":\"%s\"}",
							i? ",": "", arch, bits,
							boffset, obj_size, machine);
					break;
				default:
					bin->cb_printf ("%03i 0x%08" PFMT64x " %d %s_%d\n", i,
							boffset, obj_size, arch, bits);
				}
				snprintf (archline, sizeof (archline),
					"0x%08" PFMT64x ":%d:%s:%d",
					boffset, obj_size, arch, bits);
			} else if (nbinfile && mode) {
				switch (mode) {
				case 'q':
					bin->cb_printf ("%s\n", arch);
					break;
				case 'j':
					bin->cb_printf ("%s{\"arch\":\"unk_%d\",\"bits\":%d,"
							"\"offset\":%" PFMT64d ",\"size\":%d,"
							"\"machine\":\"%s\"}",
							i? ",": "", i, bits,
							boffset, obj_size, machine);
					break;
				default:
					bin->cb_printf ("%03i 0x%08" PFMT64x " %d unk_0\n", i,
							boffset, obj_size);
				}
				snprintf (archline, sizeof (archline),
					"0x%08" PFMT64x ":%d:%s:%d",
					boffset, obj_size, "unk", 0);
			} else {
				eprintf ("Error: Invalid RBinFile.\n");
			}
			//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
		}
	}
	if (mode == 'j') {
		bin->cb_printf ("]");
	}
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static RBinSection* _get_vsection_at(RBin *bin, ut64 vaddr) {
	RBinObject *cur = r_bin_object_get_cur (bin);
	return r_bin_get_section_at (cur, vaddr, true);
}

R_API void r_bin_bind(RBin *bin, RBinBind *b) {
	if (b) {
		b->bin = bin;
		b->get_offset = getoffset;
		b->get_name = getname;
		b->get_sections = r_bin_get_sections;
		b->get_vsect_at = _get_vsection_at;
	}
}

R_API RBuffer *r_bin_create(RBin *bin, const ut8 *code, int codelen,
			     const ut8 *data, int datalen) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (codelen < 0) {
		codelen = 0;
	}
	if (datalen < 0) {
		datalen = 0;
	}
	if (plugin && plugin->create) {
		return plugin->create (bin, code, codelen, data, datalen);
	}
	return NULL;
}

R_API RBuffer *r_bin_package(RBin *bin, const char *type, const char *file, RList *files) {
	if (!strcmp (type, "zip")) {
#if 0
		int zep = 0;
		struct zip * z = zip_open (file, 8 | 1, &zep);
		if (z) {
			RListIter *iter;
			const char *f;
			eprintf ("zip file created\n");
			r_list_foreach (files, iter, f) {
				struct zip_source *zs = NULL;
				zs = zip_source_file (z, f, 0, 1024);
				if (zs) {
					eprintf ("ADD %s\n", f);
					zip_add (z, f, zs);
					zip_source_free (zs);
				} else {
					eprintf ("Cannot find file %s\n", f);
				}
				eprintf ("zS %p\n", zs);
			}
			zip_close (z);
		} else {
			eprintf ("Cannot create zip file\n");
		}
#endif
	} else if (!strcmp (type, "fat")) {
		const char *f;
		RListIter *iter;
		ut32 num;
		ut8 *num8 = (ut8*)&num;
		RBuffer *buf = r_buf_new_file (file, true);
		r_buf_write_at (buf, 0, (const ut8*)"\xca\xfe\xba\xbe", 4);
		int count = r_list_length (files);

		num = r_read_be32 (&count);
		ut64 from = 0x1000;
		r_buf_write_at (buf, 4, num8, 4);
		int off = 12;
		int item = 0;
		r_list_foreach (files, iter, f) {
			int f_len = 0;
			ut8 *f_buf = (ut8 *)r_file_slurp (f, &f_len);
			if (f_buf && f_len >= 0) {
				eprintf ("ADD %s %d\n", f, f_len);
			} else {
				eprintf ("Cannot open %s\n", f);
				free (f_buf);
				continue;
			}
			item++;
			/* CPU */
			num8[0] = f_buf[7];
			num8[1] = f_buf[6];
			num8[2] = f_buf[5];
			num8[3] = f_buf[4];
			r_buf_write_at (buf, off - 4, num8, 4);
			/* SUBTYPE */
			num8[0] = f_buf[11];
			num8[1] = f_buf[10];
			num8[2] = f_buf[9];
			num8[3] = f_buf[8];
			r_buf_write_at (buf, off, num8, 4);
			ut32 from32 = from;
			/* FROM */
			num = r_read_be32 (&from32);
			r_buf_write_at (buf, off + 4, num8, 4);
			r_buf_write_at (buf, from, f_buf, f_len);
			/* SIZE */
			num = r_read_be32 (&f_len);
			r_buf_write_at (buf, off + 8, num8, 4);
			off += 20;
			from += f_len + (f_len % 0x1000);
			free (f_buf);
		}
		r_buf_free (buf);
		return NULL;
	} else {
		eprintf ("Usage: rabin2 -X [fat|zip] [filename] [files ...]\n");
	}
	return NULL;
}

R_API RBinObject *r_bin_get_object(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) {
		o->referenced++;
	}
	return o;
}

R_API RList * /*<RBinClass>*/ r_bin_get_classes(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->classes: NULL;
}

R_API void r_bin_class_free(RBinClass *c) {
	free (c->name);
	free (c->super);
	r_list_free (c->methods);
	r_list_free (c->fields);
	free (c);
}

R_API RBinClass *r_bin_class_new(RBinFile *binfile, const char *name,
				  const char *super, int view) {
	RBinObject *o = binfile? binfile->o: NULL;
	RList *list = NULL;
	RBinClass *c;
	if (!o) {
		return NULL;
	}
	list = o->classes;
	if (!name) {
		return NULL;
	}
	c = r_bin_class_get (binfile, name);
	if (c) {
		if (super) {
			free (c->super);
			c->super = strdup (super);
		}
		return c;
	}
	c = R_NEW0 (RBinClass);
	if (!c) {
		return NULL;
	}
	c->name = strdup (name);
	c->super = super? strdup (super): NULL;
	c->index = r_list_length (list);
	c->methods = r_list_new ();
	c->fields = r_list_new ();
	c->visibility = view;
	if (!list) {
		list = o->classes = r_list_new ();
	}
	r_list_append (list, c);
	return c;
}

R_API RBinClass *r_bin_class_get(RBinFile *binfile, const char *name) {
	if (!binfile || !binfile->o || !name) {
		return NULL;
	}
	RBinClass *c;
	RListIter *iter;
	RList *list = binfile->o->classes;
	r_list_foreach (list, iter, c) {
		if (!strcmp (c->name, name)) {
			return c;
		}
	}
	return NULL;
}

R_API RBinSymbol *r_bin_class_add_method(RBinFile *binfile, const char *classname, const char *name, int nargs) {
	RBinClass *c = r_bin_class_get (binfile, classname);
	if (!c) {
		c = r_bin_class_new (binfile, classname, NULL, 0);
		if (!c) {
			eprintf ("Cannot allocate class %s\n", classname);
			return NULL;
		}
	}
	RBinSymbol *m;
	RListIter *iter;
	r_list_foreach (c->methods, iter, m) {
		if (!strcmp (m->name, name)) {
			return NULL;
		}
	}
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (!sym) {
		return NULL;
	}
	sym->name = strdup (name);
	r_list_append (c->methods, sym);
	return sym;
}

R_API void r_bin_class_add_field(RBinFile *binfile, const char *classname, const char *name) {
	//TODO: add_field into class
	//eprintf ("TODO add field: %s \n", name);
}

/* returns vaddr, rebased with the baseaddr of binfile, if va is enabled for
 * bin, paddr otherwise */
R_API ut64 r_bin_file_get_vaddr(RBinFile *binfile, ut64 paddr, ut64 vaddr) {
	int use_va = 0;
	if (binfile && binfile->o && binfile->o->info) {
		use_va = binfile->o->info->has_va;
	}
	return use_va? binobj_a2b (binfile->o, vaddr): paddr;
}

/* returns vaddr, rebased with the baseaddr of bin, if va is enabled for bin,
 * paddr otherwise */
R_API ut64 r_bin_get_vaddr(RBin *bin, ut64 paddr, ut64 vaddr) {
	if (!bin) {
		return UT64_MAX;
	}
	if (paddr == UT64_MAX) {
		return UT64_MAX;
	}
	if (!bin->cur) {
		return paddr;
	}
	/* hack to realign thumb symbols */
	if (bin->cur->o && bin->cur->o->info && bin->cur->o->info->arch) {
		if (bin->cur->o->info->bits == 16) {
			RBinSection *s = r_bin_get_section_at (bin->cur->o, paddr, false);
			// autodetect thumb
			if (s && s->srwx & 1 && strstr (s->name, "text")) {
				if (!strcmp (bin->cur->o->info->arch, "arm") && (vaddr & 1)) {
					vaddr = (vaddr >> 1) << 1;
				}
			}
		}
	}
	return r_bin_file_get_vaddr (bin->cur, paddr, vaddr);
}

R_API ut64 r_bin_a2b(RBin *bin, ut64 addr) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->baddr_shift + addr: addr;
}

R_API ut64 r_bin_get_size(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->size : 0;
}

R_API RBinFile *r_bin_cur(RBin *bin) {
	return bin? bin->cur: NULL;
}

R_API RBinObject *r_bin_cur_object(RBin *bin) {
	RBinFile *binfile = r_bin_cur (bin);
	return binfile? binfile->o: NULL;
}

R_API void r_bin_force_plugin(RBin *bin, const char *name) {
	free (bin->force);
	bin->force = (name && *name)? strdup (name): NULL;
}

R_API int r_bin_read_at(RBin *bin, ut64 addr, ut8 *buf, int size) {
	RIOBind *iob;
	if (!bin || !(iob = &(bin->iob))) {
		return false;
	}
	return iob->read_at (iob->io, addr, buf, size);
}

R_API int r_bin_write_at(RBin *bin, ut64 addr, const ut8 *buf, int size) {
	RIOBind *iob;
	if (!bin || !(iob = &(bin->iob))) {
		return false;
	}
	return iob->write_at (iob->io, addr, buf, size);
}

R_API const char *r_bin_entry_type_string(int etype) {
	switch (etype) {
	case R_BIN_ENTRY_TYPE_PROGRAM:
		return "program";
	case R_BIN_ENTRY_TYPE_MAIN:
		return "main";
	case R_BIN_ENTRY_TYPE_INIT:
		return "init";
	case R_BIN_ENTRY_TYPE_FINI:
		return "fini";
	case R_BIN_ENTRY_TYPE_TLS:
		return "tls";
	case R_BIN_ENTRY_TYPE_PREINIT:
		return "preinit";
	}
	return NULL;
}

R_API void r_bin_load_filter(RBin *bin, ut64 rules) {
	bin->filter_rules = rules;
}

/* RBinField */
R_API RBinField *r_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format) {
	RBinField *ptr;
	if (!(ptr = R_NEW0 (RBinField))) {
		return NULL;
	}
	ptr->name = strdup (name);
	ptr->comment = (comment && *comment)? strdup (comment): NULL;
	ptr->format = (format && *format)? strdup (format): NULL;
	ptr->paddr = paddr;
	ptr->size = size;
//	ptr->visibility = ???
	ptr->vaddr = vaddr;
	return ptr;
}

// use void* to honor the RListFree signature
R_API void r_bin_field_free(void *_field) {
	RBinField *field = (RBinField*) _field;
	free (field->name);
	free (field->comment);
	free (field->format);
	free (field);
}

R_API const char *r_bin_get_meth_flag_string(ut64 flag, bool compact) {
	switch (flag) {
	case R_BIN_METH_CLASS:
		return compact ? "c" : "class";
	case R_BIN_METH_STATIC:
		return compact ? "s" : "static";
	case R_BIN_METH_PUBLIC:
		return compact ? "p" : "public";
	case R_BIN_METH_PRIVATE:
		return compact ? "P" : "private";
	case R_BIN_METH_PROTECTED:
		return compact ? "r" : "protected";
	case R_BIN_METH_INTERNAL:
		return compact ? "i" : "internal";
	case R_BIN_METH_OPEN:
		return compact ? "o" : "open";
	case R_BIN_METH_FILEPRIVATE:
		return compact ? "e" : "fileprivate";
	case R_BIN_METH_FINAL:
		return compact ? "f" : "final";
	case R_BIN_METH_VIRTUAL:
		return compact ? "v" : "virtual";
	case R_BIN_METH_CONST:
		return compact ? "k" : "const";
	case R_BIN_METH_MUTATING:
		return compact ? "m" : "mutating";
	case R_BIN_METH_ABSTRACT:
		return compact ? "a" : "abstract";
	case R_BIN_METH_SYNCHRONIZED:
		return compact ? "y" : "synchronized";
	case R_BIN_METH_NATIVE:
		return compact ? "n" : "native";
	case R_BIN_METH_BRIDGE:
		return compact ? "b" : "bridge";
	case R_BIN_METH_VARARGS:
		return compact ? "g" : "varargs";
	case R_BIN_METH_SYNTHETIC:
		return compact ? "h" : "synthetic";
	case R_BIN_METH_STRICT:
		return compact ? "t" : "strict";
	case R_BIN_METH_MIRANDA:
		return compact ? "A" : "miranda";
	case R_BIN_METH_CONSTRUCTOR:
		return compact ? "C" : "constructor";
	case R_BIN_METH_DECLARED_SYNCHRONIZED:
		return compact ? "Y" : "declared_synchronized";
	default:
		return NULL;
	}
}
