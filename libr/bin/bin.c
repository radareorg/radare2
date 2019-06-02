/* radare2 - LGPL - Copyright 2009-2019 - pancake, nibble, dso */

#include <r_bin.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_io.h>
#include <config.h>
#include "i/private.h"

R_LIB_VERSION (r_bin);

#define DB a->sdb;
#define RBINLISTFREE(x)\
	if (x) { \
		r_list_free (x);\
		(x) = NULL;\
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
	return o ? addr + o->baddr_shift : addr;
}

// TODO: move these two function do a different file
R_API RBinXtrData *r_bin_xtrdata_new(RBuffer *buf, ut64 offset, ut64 size, ut32 file_count, RBinXtrMetadata *metadata) {
	RBinXtrData *data = R_NEW0 (RBinXtrData);
	if (data) {
		data->offset = offset;
		data->size = size;
		data->file_count = file_count;
		data->metadata = metadata;
		data->loaded = 0;
// dont slice twice TODO. review this
		data->buf = r_buf_ref (buf); // r_buf_new_slice (buf, offset, size);
	}
	return data;
}

R_API const char *r_bin_string_type(int type) {
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
	r_return_if_fail (data);
	if (data->metadata) {
		free (data->metadata->libname);
		free (data->metadata->arch);
		free (data->metadata->machine);
		free (data->metadata);
	}
	free (data->file);
	r_buf_free (data->buf);
	free (data);
}

R_API RList *r_bin_raw_strings(RBinFile *bf, int min) {
	r_return_val_if_fail (bf, NULL);
	return r_bin_file_get_strings (bf, min, 0, 2);
}

R_API RList *r_bin_dump_strings(RBinFile *bf, int min, int raw) {
	r_return_val_if_fail (bf, NULL);
	return r_bin_file_get_strings (bf, min, 1, raw);
}

R_API void r_bin_options_init(RBinOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, int rawstr) {
	memset (opt, 0, sizeof (*opt));
	opt->baseaddr = baseaddr;
	opt->loadaddr = loadaddr;
	opt->fd = fd;
	opt->rawstr = rawstr;
}

R_API void r_bin_arch_options_init(RBinArchOptions *opt, const char *arch, int bits) {
	opt->arch = arch? arch: R_SYS_ARCH;
	opt->bits = bits? bits: R_SYS_BITS;
}

R_API void r_bin_file_hash_free(RBinFileHash *fhash) {
	if (fhash) {
		R_FREE (fhash->type);
		R_FREE (fhash->hex);
		free (fhash);
	}
}

R_API void r_bin_info_free(RBinInfo *rb) {
	if (!rb) {
		return;
	}

	r_list_free (rb->file_hashes);
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
	free (rb->actual_checksum);
	free (rb->claimed_checksum);
	free (rb->compiler);
	free (rb);
}

R_API RBinImport *r_bin_import_clone(RBinImport *o) {
	r_return_val_if_fail (o, NULL);

	RBinImport *res = r_mem_dup (o, sizeof (*o));
	if (res) {
		res->name = R_STR_DUP (o->name);
		res->classname = R_STR_DUP (o->classname);
		res->descriptor = R_STR_DUP (o->descriptor);
	}
	return res;
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

R_API const char *r_bin_symbol_name(RBinSymbol *s) {
	if (s->dup_count) {
		return sdb_fmt ("%s_%d", s->name, s->dup_count);
	}
	return s->name;
}

R_API void r_bin_symbol_free(void *_sym) {
	RBinSymbol *sym = (RBinSymbol *)_sym;
	if (sym) {
		free (sym->name);
		free (sym->classname);
		free (sym);
	}
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
R_API bool r_bin_open(RBin *bin, const char *file, RBinOptions *opt) {
	r_return_val_if_fail (bin && bin->iob.io && opt, false);

	RIOBind *iob = &(bin->iob);
	if (!iob->desc_get (iob->io, opt->fd)) {
		opt->fd = iob->fd_open (iob->io, file, R_PERM_R, 0644);
	}
	if (opt->fd < 0) {
		eprintf ("Couldn't open bin for file '%s'\n", file);
		return false;
	}
	opt->offset = 0;
	opt->sz = 0;
	opt->pluginname = NULL;
	return r_bin_open_io (bin, opt);
}

// XXX this function is full of mess, shuold be rewritten after the refactorings
R_API bool r_bin_reload(RBin *bin, int fd, ut64 baseaddr) {
	RIOBind *iob = &(bin->iob);
	int res = false;
	ut8 *buf_bytes = NULL;

	r_return_val_if_fail (bin && iob && iob->io, false);

	const char *name = iob->fd_get_name (iob->io, fd);
	RBinFile *bf = r_bin_file_find_by_name (bin, name);
	if (!bf) {
		eprintf ("r_bin_reload: No file to reopen\n");
		goto error;
	}
	RBinOptions opt;
	r_bin_options_init (&opt, fd, baseaddr, bf->loadaddr, bin->rawstr);
	if (bf->o) {
		opt.offset = bf->o->boffset;
	}

	// invalidate current object reference
	bf->o = NULL;
	ut64 sz = iob->fd_size (iob->io, fd);
	if (sz == UT64_MAX) {
		sz = 128 * 1024;
	}
	// TODO: deprecate, the code in the else should be enough
	if (sz == UT64_MAX) {
		if (!iob->fd_is_dbg (iob->io, fd)) {
			// too big, probably wrong
			eprintf ("Warning: file is too big and not in debugger\n");
			goto error;
		}
		// attempt a local open and read
		// This happens when a plugin like debugger does not have a
		// fixed size.
		// if there is no fixed size or its MAXED, there is no way to
		// definitively
		// load the bin-properly.  Many of the plugins require all
		// content and are not
		// stream based loaders
		int tfd = iob->fd_open (iob->io, name, R_PERM_R, 0);
		if (tfd < 0) {
			goto error;
		}
		sz = iob->fd_size (iob->io, tfd);
		if (sz == UT64_MAX) {
			iob->fd_close (iob->io, tfd);
			goto error;
		}
		res = r_bin_open_io (bin, &opt);
		iob->fd_close (iob->io, tfd);
		goto error;
	} else {
		buf_bytes = calloc (1, sz + 1);
		if (!buf_bytes) {
			goto error;
		}
		if (!iob->fd_read_at (iob->io, fd, 0LL, buf_bytes, sz)) {
			free (buf_bytes);
			goto error;
		}
	}
	r_bin_file_set_bytes (bf, buf_bytes, sz, false);
	free (buf_bytes);

	return r_bin_open_io (bin, &opt);
error:
	return false;
}

R_API bool r_bin_open_io(RBin *bin, RBinOptions *opt) {
	r_return_val_if_fail (bin && opt && bin->iob.io, false);
	r_return_val_if_fail (opt->fd >= 0 && (st64)opt->sz >= 0, false);

	RIOBind *iob = &(bin->iob);
	RIO *io = iob? iob->io: NULL;
	RListIter *it;
	RBinXtrPlugin *xtr;
	int tfd = opt->fd;

	bool is_debugger = iob->fd_is_dbg (io, opt->fd);
	const char *fname = iob->fd_get_name (io, opt->fd);

	bin->rawstr = opt->rawstr;
	if (opt->loadaddr == UT64_MAX) {
		opt->loadaddr = 0;
	}
	ut64 file_sz = iob->fd_size (io, opt->fd);
	if (file_sz == UT64_MAX) {
		if (is_debugger) {
			tfd = iob->fd_open (io, fname, R_PERM_R, 0644);
			if (tfd >= 1) {
				file_sz = iob->fd_size (io, tfd);
			}
		} else {
			if (bin->verbose) {
				eprintf ("r_bin_open_io: unknown filesize may fail here..\n");
			}
			return false;
		}
	}
	if (!opt->sz) {
		opt->sz = file_sz;
	}
	// check if blockdevice?
	if (opt->sz >= UT32_MAX) {
		opt->sz = 1024 * 32;
	}
	RBuffer *buf = r_buf_new_with_io (&bin->iob, tfd);
	if (!buf) {
		return false;
	}
	bin->file = fname;
	opt->sz = R_MIN (file_sz, opt->sz);
	ut64 seekaddr = opt->loadaddr;

	if (!is_debugger && seekaddr > 0 && seekaddr != UT64_MAX) {
		// slice buffer if necessary
		RBuffer *nb = r_buf_new_slice (buf, seekaddr, opt->sz);
		if (nb) {
			r_buf_free (buf);
			buf = nb;
		}
	}

	RBinFile *bf = NULL;
	if (bin->use_xtr && !opt->pluginname && (st64)opt->sz > 0) {
		// XXX - for the time being this is fine, but we may want to
		// change the name to something like
		// <xtr_name>:<bin_type_name>
		r_list_foreach (bin->binxtrs, it, xtr) {
			if (!xtr->check_buffer) {
				eprintf ("Missing check_buffer callback for '%s'\n", xtr->name);
				continue;
			}
			if (xtr->check_buffer (buf)) {
				if (xtr->extract_from_buffer || xtr->extractall_from_buffer ||
				    xtr->extract_from_bytes || xtr->extractall_from_bytes) {
					if (is_debugger && opt->sz != file_sz) {
						if (tfd < 0) {
							tfd = iob->fd_open (io, fname, R_PERM_R, 0);
						}
						opt->sz = iob->fd_size (io, tfd);
						if (opt->sz != UT64_MAX) {
							r_buf_seek (buf, 0, R_BUF_SET);
							//buf->base_priv = 0;
						}
						// DOUBLECLOSE UAF : iob->fd_close (io, tfd);
						tfd = -1; // marking it closed
					}
					bf = r_bin_file_xtr_load_buffer (bin, xtr,
						fname, buf, file_sz,
						opt->baseaddr, opt->loadaddr, opt->xtr_idx,
						opt->fd, bin->rawstr);
				}
			}
		}
	}
	if (!bf) {
		bf = r_bin_file_new_from_buffer (
			bin, fname, buf, file_sz, bin->rawstr,
			opt->baseaddr, opt->loadaddr, opt->fd, opt->pluginname, opt->offset);
		if (!bf) {
			return false;
		}
	}
	if (!r_bin_file_set_cur_binfile (bin, bf)) {
		return false;
	}
	r_id_storage_set (bin->ids, bin->cur, bf->id);
	return true;
}

R_IPI RBinPlugin *r_bin_get_binplugin_by_name(RBin *bin, const char *name) {
	RBinPlugin *plugin;
	RListIter *it;

	r_return_val_if_fail (bin && name, NULL);

	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, name)) {
			return plugin;
		}
	}
	return NULL;
}

// XXX this api must die. See #11920
R_API RBinPlugin *r_bin_get_binplugin_by_bytes(RBin *bin, const ut8 *bytes, ut64 sz) {
	RBinPlugin *plugin;
	RListIter *it;

eprintf ("r_bin_get_binplugin_by_bytes is deprecated. Use r_bin_get_binplugin_by_buffer instead\n");
	r_return_val_if_fail (bin && bytes, NULL);

	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->check_buffer) {
			RBuffer *b = r_buf_new_with_pointers (bytes, sz, false);
			if (b) {
				bool ok = plugin->check_buffer (b);
				r_buf_free (b);
				if (ok) {
					return plugin;
				}
			}
		} else if (plugin->check_bytes && plugin->check_bytes (bytes, sz)) {
			return plugin;
		}
	}
	return NULL;
}

R_API RBinPlugin *r_bin_get_binplugin_by_buffer(RBin *bin, RBuffer *buf) {
	RBinPlugin *plugin;
	RListIter *it;

	r_return_val_if_fail (bin && buf, NULL);

	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->check_buffer) {
			if (plugin->check_buffer (buf)) {
				return plugin;
			}
		} else if (plugin->check_bytes) {
			eprintf ("Deprecate plugin->check_bytes for '%s' please\n", plugin->name);
			ut64 sz;
			const ut8 *bytes = r_buf_data (buf, &sz);
			if (plugin->check_bytes (bytes, sz)) {
				return plugin;
			}
		}
	}
	return NULL;
}

R_IPI RBinXtrPlugin *r_bin_get_xtrplugin_by_name(RBin *bin, const char *name) {
	RBinXtrPlugin *xtr;
	RListIter *it;

	r_return_val_if_fail (bin && name, NULL);

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

// TODO: deprecate
R_IPI RBinPlugin *r_bin_get_binplugin_any(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinPlugin *res = r_bin_get_binplugin_by_name (bin, "any");
	r_warn_if_fail (res);
	return res;
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

	r_return_val_if_fail (bin && foo, false);

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

	r_return_val_if_fail (bin && foo, false);

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

	r_return_val_if_fail (bin && foo, false);

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

	r_return_val_if_fail (bin && name, false);

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
	r_return_val_if_fail (bin, UT64_MAX);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? r_bin_object_get_baddr (o) : UT64_MAX;
}

/* returns the load address of bin or UT64_MAX in case of errors */
R_API ut64 r_bin_get_laddr(RBin *bin) {
	r_return_val_if_fail (bin, UT64_MAX);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->loadaddr : UT64_MAX;
}

R_API void r_bin_set_baddr(RBin *bin, ut64 baddr) {
	r_return_if_fail (bin);
	RBinObject *o = r_bin_cur_object (bin);
	if (o) {
		r_bin_object_set_baddr (o, baddr);
	}
	// XXX - update all the infos?
}

R_API RBinAddr *r_bin_get_sym(RBin *bin, int sym) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	if (sym < 0 || sym >= R_BIN_SYM_LAST) {
		return NULL;
	}
	return o? o->binsym[sym]: NULL;
}

// XXX: those accessors are redundant
R_API RList *r_bin_get_entries(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->entries : NULL;
}

R_API RList *r_bin_get_fields(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->fields : NULL;
}

R_API RList *r_bin_get_imports(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->imports : NULL;
}

R_API RBinInfo *r_bin_get_info(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->info : NULL;
}

R_API RList *r_bin_get_libs(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->libs : NULL;
}

static RList *relocs_rbtree2list(RBNode *root) {
	RList *res = r_list_new ();
	RBinReloc *reloc;
	RBIter it;

	r_rbtree_foreach (root, it, reloc, RBinReloc, vrb) {
		r_list_append (res, reloc);
	}
	return res;
}

R_API RBNode *r_bin_patch_relocs(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o? r_bin_object_patch_relocs (bin, o): NULL;
}

// return a list of <const RBinReloc> that needs to be freed by the caller
R_API RList *r_bin_patch_relocs_list(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBNode *root = r_bin_patch_relocs (bin);
	return root? relocs_rbtree2list (root): NULL;
}

R_API RBNode *r_bin_get_relocs(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->relocs : NULL;
}

// return a list of <const RBinReloc> that needs to be freed by the caller
R_API RList *r_bin_get_relocs_list(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBNode *root = r_bin_get_relocs (bin);
	return root? relocs_rbtree2list (root): NULL;
}

R_API RList *r_bin_get_sections(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->sections : NULL;
}

R_API RBinSection *r_bin_get_section_at(RBinObject *o, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;

	r_return_val_if_fail (o, NULL);
	// TODO: must be O(1) .. use sdb here
	r_list_foreach (o->sections, iter, section) {
		from = va ? binobj_a2b (o, section->vaddr) : section->paddr;
		to = va ? (binobj_a2b (o, section->vaddr) + section->vsize) : (section->paddr + section->size);
		if (off >= from && off < to) {
			return section;
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
		o->strings = r_bin_file_get_strings (a, bin->minstrlen, 0, a->rawstr);
	}
	if (bin->debase64) {
		r_bin_object_filter_strings (o);
	}
	return o->strings;
}

R_API RList *r_bin_get_strings(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->strings : NULL;
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

R_API RList *r_bin_get_symbols(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->symbols: NULL;
}

R_API RList *r_bin_get_mem(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->mem : NULL;
}

R_API int r_bin_is_big_endian(RBin *bin) {
	r_return_val_if_fail (bin, -1);
	RBinObject *o = r_bin_cur_object (bin);
	return (o && o->info) ? o->info->big_endian : -1;
}

R_API int r_bin_is_static(RBin *bin) {
	r_return_val_if_fail (bin, false);
	RBinObject *o = r_bin_cur_object (bin);
	if (o && o->libs && r_list_length (o->libs) > 0) {
		return R_BIN_DBG_STATIC & o->info->dbg_info;
	}
	return true;
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

R_API bool r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	r_return_val_if_fail (bin && arch, false);

	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits);
	if (!binfile) {
		R_LOG_WARN ("Cannot find binfile with arch/bits %s/%d\n", arch, bits);
		return false;
	}

	RBinObject *obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	if (!obj && binfile->xtr_data) {
		RBinXtrData *xtr_data = r_list_get_n (binfile->xtr_data, 0);
		if (xtr_data && !xtr_data->loaded) {
			if (!r_bin_file_object_new_from_xtr_data (bin, binfile,
				    UT64_MAX, r_bin_get_laddr (bin), xtr_data)) {
				return false;
			}
		}
		obj = binfile->o;
	}
	return r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API bool r_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	r_return_val_if_fail (bin, false);

	RBinFile *cur = r_bin_cur (bin);
	RBinObject *obj = NULL;
	name = !name && cur? cur->file: name;
	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits);
	if (binfile && name) {
		obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	}
	return r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API int r_bin_select_object(RBinFile *binfile, const char *arch, int bits, const char *name) {
	r_return_val_if_fail (binfile, false);
	RBinObject *obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	return r_bin_file_set_cur_binfile_obj (binfile->rbin, binfile, obj);
}

// NOTE: this functiona works as expected, but  we need to merge bfid and boid
R_API bool r_bin_select_by_ids(RBin *bin, ut32 binfile_id) {
	r_return_val_if_fail (bin, false);
	if (binfile_id == UT32_MAX) {
		return false;
	}
	RBinFile *bf = r_bin_file_find_by_id (bin, binfile_id);
	return bf? r_bin_file_set_cur_binfile_obj (bin, bf, NULL): false;
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
	r_return_if_fail (bin);

	int i = 0;
	char unk[128];
	char archline[128];
	RBinFile *binfile = r_bin_cur (bin);
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
	}
	if (!binfile) {
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
	RBinObject *obj = nbinfile->o;
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
	if (mode == 'j') {
		bin->cb_printf ("]");
	}
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static RBinSection* _get_vsection_at(RBin *bin, ut64 vaddr) {
	if (!bin || !bin->cur) {
		return NULL;
	}
	RBinObject *cur = bin->cur->o;
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

R_API RBuffer *r_bin_create(RBin *bin, const char *plugin_name,
	const ut8 *code, int codelen, const ut8 *data, int datalen,
	RBinArchOptions *opt) {

	r_return_val_if_fail (bin && plugin_name && opt, NULL);

	RBinPlugin *plugin = r_bin_get_binplugin_by_name (bin, plugin_name);
	if (!plugin) {
		R_LOG_WARN ("Cannot find RBin plugin named '%s'.\n", plugin_name);
		return NULL;
	}
	if (!plugin->create) {
		R_LOG_WARN ("RBin plugin '%s' does not implement \"create\" method.\n", plugin_name);
		return NULL;
	}

	if (codelen < 0) {
		codelen = 0;
	}
	if (datalen < 0) {
		datalen = 0;
	}
	return plugin->create (bin, code, codelen, data, datalen, opt);
}

R_API RBuffer *r_bin_package(RBin *bin, const char *type, const char *file, RList *files) {
	if (!strcmp (type, "zip")) {
		// XXX: implement me
		r_warn_if_reached ();
	} else if (!strcmp (type, "fat")) {
		const char *f;
		RListIter *iter;
		ut32 num;
		ut8 *num8 = (ut8*)&num;
		RBuffer *buf = r_buf_new_file (file, O_RDWR | O_CREAT, 0644);
		if (!buf) {
			eprintf ("Cannot open file %s - Permission Denied.\n", file);
			return NULL;
		}
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

R_API RList * /*<RBinClass>*/ r_bin_get_classes(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->classes : NULL;
}

R_IPI void r_bin_class_free(RBinClass *c) {
	free (c->name);
	free (c->super);
	r_list_free (c->methods);
	r_list_free (c->fields);
	free (c);
}

static RBinClass *class_get(RBinFile *binfile, const char *name) {
	r_return_val_if_fail (binfile && binfile->o && name, NULL);
	if (!binfile->o->classes_ht) {
		return NULL;
	}
	return ht_pp_find (binfile->o->classes_ht, name, NULL);
}

R_IPI RBinClass *r_bin_class_new(RBinFile *binfile, const char *name, const char *super, int view) {
	if (!binfile || !binfile->o) {
		return NULL;
	}
	RBinObject *o = binfile->o;
	RList *list = o->classes;
	if (!name) {
		return NULL;
	}
	RBinClass *c = class_get (binfile, name);
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
	if (!list) {
		list = o->classes = r_list_new ();
	}
	if (!o->classes_ht) {
		o->classes_ht = ht_pp_new0 ();
	}
	c->name = strdup (name);
	c->super = super? strdup (super): NULL;
	c->index = r_list_length (list);
	c->methods = r_list_new ();
	c->fields = r_list_new ();
	c->visibility = view;
	r_list_append (list, c);
	ht_pp_insert (o->classes_ht, name, c);
	return c;
}

R_IPI RBinSymbol *r_bin_class_add_method(RBinFile *binfile, const char *classname, const char *name, int nargs) {
	r_return_val_if_fail (binfile, NULL);

	RBinClass *c = class_get (binfile, classname);
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

R_IPI void r_bin_class_add_field(RBinFile *binfile, const char *classname, const char *name) {
	//TODO: add_field into class
	//eprintf ("TODO add field: %s \n", name);
}

/* returns vaddr, rebased with the baseaddr of binfile, if va is enabled for
 * bin, paddr otherwise */
R_API ut64 r_bin_file_get_vaddr(RBinFile *binfile, ut64 paddr, ut64 vaddr) {
	r_return_val_if_fail (binfile, paddr);

	if (binfile->o && binfile->o->info && binfile->o->info->has_va) {
		return binobj_a2b (binfile->o, vaddr);
	}
	return paddr;
}

/* returns vaddr, rebased with the baseaddr of bin, if va is enabled for bin,
 * paddr otherwise */
R_API ut64 r_bin_get_vaddr(RBin *bin, ut64 paddr, ut64 vaddr) {
	r_return_val_if_fail (bin && paddr != UT64_MAX, UT64_MAX);

	if (!bin->cur) {
		return paddr;
	}
	/* hack to realign thumb symbols */
	if (bin->cur->o && bin->cur->o->info && bin->cur->o->info->arch) {
		if (bin->cur->o->info->bits == 16) {
			RBinSection *s = r_bin_get_section_at (bin->cur->o, paddr, false);
			// autodetect thumb
			if (s && (s->perm & R_PERM_X) && strstr (s->name, "text")) {
				if (!strcmp (bin->cur->o->info->arch, "arm") && (vaddr & 1)) {
					vaddr = (vaddr >> 1) << 1;
				}
			}
		}
	}
	return r_bin_file_get_vaddr (bin->cur, paddr, vaddr);
}

R_API ut64 r_bin_a2b(RBin *bin, ut64 addr) {
	r_return_val_if_fail (bin, UT64_MAX);
	RBinObject *o = r_bin_cur_object (bin);
	return binobj_a2b (o, addr);
}

R_API ut64 r_bin_get_size(RBin *bin) {
	r_return_val_if_fail (bin, UT64_MAX);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->size : 0;
}

R_API RBinFile *r_bin_cur(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	return bin->cur;
}

R_API RBinObject *r_bin_cur_object(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinFile *binfile = r_bin_cur (bin);
	return binfile ? binfile->o : NULL;
}

R_API void r_bin_force_plugin(RBin *bin, const char *name) {
	r_return_if_fail (bin);
	free (bin->force);
	bin->force = (name && *name) ? strdup (name) : NULL;
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

R_IPI void r_bin_section_free(RBinSection *bs) {
	free (bs->name);
	free (bs->format);
	free (bs);
}
