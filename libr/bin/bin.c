/* radare2 - LGPL - Copyright 2009-2023 - pancake, nibble, dso */

#define R_LOG_ORIGIN "bin"

#include <r_bin.h>
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

static int __getoffset(RBin *bin, int type, int idx) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (plugin && plugin->get_offset) {
		return plugin->get_offset (a, type, idx);
	}
	return -1;
}

static const char *__getname(RBin *bin, int type, int idx, bool sd) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (plugin && plugin->get_name) {
		return plugin->get_name (a, type, idx, sd);
	}
	return NULL;
}

// TODO: move these two function do a different file
R_API RBinXtrData *r_bin_xtrdata_new(RBuffer *buf, ut64 offset, ut64 size, ut32 file_count, RBinXtrMetadata *metadata) {
	RBinXtrData *data = R_NEW0 (RBinXtrData);
	if (data) {
		data->offset = offset;
		data->size = size;
		data->file_count = file_count;
		data->metadata = metadata;
		data->loaded = false;
		// don't slice twice TODO. review this
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
	if (data) {
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
}

R_API RList *r_bin_raw_strings(RBinFile *bf, int min) {
	r_return_val_if_fail (bf, NULL);
	return r_bin_file_get_strings (bf, min, 0, 2);
}

R_API RList *r_bin_dump_strings(RBinFile *bf, int min, int raw) {
	r_return_val_if_fail (bf, NULL);
	return r_bin_file_get_strings (bf, min, 1, raw);
}

R_API void r_bin_file_options_init(RBinFileOptions *opt, int fd, ut64 baseaddr, ut64 loadaddr, int rawstr) {
	r_return_if_fail (opt);
	memset (opt, 0, sizeof (*opt));
	opt->baseaddr = baseaddr;
	opt->loadaddr = loadaddr;
	opt->fd = fd;
	opt->rawstr = rawstr;
}

R_API void r_bin_arch_options_init(RBinArchOptions *opt, R_NULLABLE const char *arch, int bits) {
	r_return_if_fail (opt);
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
	free (rb->abi);
	free (rb->actual_checksum);
	free (rb->arch);
	free (rb->bclass);
	free (rb->charset);
	free (rb->claimed_checksum);
	free (rb->compiler);
	free (rb->cpu);
	free (rb->debug_file_name);
	free (rb->default_cc);
	free (rb->file);
	free (rb->flags);
	free (rb->guid);
	free (rb->intrp);
	free (rb->machine);
	free (rb->os);
	free (rb->rclass);
	free (rb->rpath);
	free (rb->subsystem);
	free (rb->type);
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

R_API void r_bin_import_free(RBinImport *imp) {
	if (imp) {
		free (imp->name);
		free (imp->libname);
		free (imp->classname);
		free (imp->descriptor);
		free (imp);
	}
}

R_API RBinSymbol *r_bin_symbol_new(const char *name, ut64 paddr, ut64 vaddr) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (sym) {
		sym->name = name? strdup (name): NULL;
		sym->paddr = paddr;
		sym->vaddr = vaddr;
	}
	return sym;
}

R_API RBinSymbol *r_bin_symbol_clone(RBinSymbol *bs) {
	r_return_val_if_fail (bs, NULL);
	RBinSymbol *nbs = R_NEW (RBinSymbol);
	memcpy (nbs, bs, sizeof (RBinSymbol));
	nbs->name = strdup (nbs->name);
	if (nbs->dname) {
		nbs->dname = strdup (nbs->dname);
	}
	if (nbs->libname) {
		nbs->libname = strdup (nbs->libname);
	}
	if (nbs->classname) {
		nbs->classname = strdup (nbs->classname);
	}
	return nbs;
}

R_API void r_bin_symbol_fini(RBinSymbol *sym) {
	free (sym->name);
	free (sym->libname);
	free (sym->classname);
}

R_API void r_bin_import_fini(RBinImport *imp) {
	if (imp) {
		free (imp->name);
		free (imp->libname);
		free (imp->classname);
		free (imp->descriptor);
	}
}

R_API void r_bin_symbol_free(void *_sym) {
	RBinSymbol *sym = (RBinSymbol *)_sym;
	if (sym) {
		r_bin_symbol_fini (sym);
		free (sym);
	}
}

R_API void r_bin_string_free(void *_str) {
	RBinString *str = (RBinString *)_str;
	if (str) {
		free (str->string);
		free (str);
	}
}

// XXX - change this to RBinObject instead of RBinFile
// makes no sense to pass in a binfile and set the RBinObject
// kinda a clunky functions
// XXX - this is a rather hacky way to do things, there may need to be a better
// way.
R_API bool r_bin_open(RBin *bin, const char *file, RBinFileOptions *opt) {
	r_return_val_if_fail (bin && bin->iob.io && opt, false);

	RIOBind *iob = &(bin->iob);
	if (!iob->desc_get (iob->io, opt->fd)) {
		opt->fd = iob->fd_open (iob->io, file, R_PERM_R, 0644);
	}
	if (opt->fd < 0) {
		R_LOG_ERROR ("Couldn't open bin for file '%s'", file);
		return false;
	}
	opt->sz = 0;
	opt->pluginname = NULL;
	return r_bin_open_io (bin, opt);
}

R_API bool r_bin_reload(RBin *bin, ut32 bf_id, ut64 baseaddr) {
	r_return_val_if_fail (bin, false);

	RBinFile *bf = r_bin_file_find_by_id (bin, bf_id);
	if (!bf) {
		R_LOG_ERROR ("r_bin_reload: No file to reopen");
		return false;
	}
	RBinFileOptions opt;
	r_bin_file_options_init (&opt, bf->fd, baseaddr, bf->loadaddr, bin->rawstr);
	opt.filename = bf->file;
	if (!bf->buf) {
		r_bin_file_delete (bin, bf->id);
		return false;
	}
	bool res = r_bin_open_buf (bin, bf->buf, &opt);
	r_bin_file_delete (bin, bf->id);
	return res;
}

R_API bool r_bin_open_buf(RBin *bin, RBuffer *buf, RBinFileOptions *opt) {
	r_return_val_if_fail (bin && opt, false);

	RListIter *it;
	RBinXtrPlugin *xtr;

	bin->rawstr = opt->rawstr;
	bin->file = opt->filename;
	if (opt->loadaddr == UT64_MAX) {
		opt->loadaddr = 0;
	}

	RBinFile *bf = NULL;
	if (bin->use_xtr && !opt->pluginname) {
		// XXX - for the time being this is fine, but we may want to
		// change the name to something like
		// <xtr_name>:<bin_type_name>
		r_list_foreach (bin->binxtrs, it, xtr) {
			if (!xtr->check) {
				R_LOG_ERROR ("Missing check callback for '%s'", xtr->meta.name);
				continue;
			}
			if (xtr->check (bf, buf)) {
				if (xtr->extract_from_buffer || xtr->extractall_from_buffer ||
				    xtr->extract_from_bytes || xtr->extractall_from_bytes) {
					bf = r_bin_file_xtr_load (bin, xtr,
						bin->file, buf, opt->baseaddr, opt->loadaddr,
						opt->xtr_idx, opt->fd, bin->rawstr);
				}
			}
		}
	}
	if (!bf) {
		// Uncomment for this speedup: 20s vs 22s
		// RBuffer *buf = r_buf_new_slurp (bin->file);
		bf = r_bin_file_new_from_buffer (bin, bin->file? bin->file: "?", buf, bin->rawstr,
			opt->baseaddr, opt->loadaddr, opt->fd, opt->pluginname);
		if (!bf) {
			return false;
		}
	}
	// r_list_append (bin->binfiles, bf); // uaf
	bool res = r_id_storage_set (bin->ids, bin->cur, bf->id);
	if (!r_bin_file_set_cur_binfile (bin, bf)) {
		R_LOG_WARN ("Cannot set the current binfile");
		return false;
	}
	// r_ref (bf);
	bin->cur = bf;
	return res;
}

R_API bool r_bin_open_io(RBin *bin, RBinFileOptions *opt) {
	r_return_val_if_fail (bin && opt && bin->iob.io, false);
	r_return_val_if_fail (opt->fd >= 0 && (st64)opt->sz >= 0, false);

	RIOBind *iob = &(bin->iob);
	RIO *io = iob? iob->io: NULL;

	bool is_debugger = iob->fd_is_dbg (io, opt->fd);
	const char *fname = iob->fd_get_name (io, opt->fd);
	if (opt->loadaddr == UT64_MAX) {
		opt->loadaddr = 0;
	}
	if (R_STR_ISEMPTY (fname)) {
		fname = "";
	}

	// Create RBuffer from the opened file
	// When debugging something, we want to open the backed file because
	// not all binary info are mapped in the virtual space. If that is not
	// possible (e.g. remote file) just try to load bin info from the
	// debugee process.
	RBuffer *buf = NULL;
	if (is_debugger) {
		buf = r_buf_new_file (fname, O_RDONLY, 0);
		is_debugger = false;
	}
	if (!buf) {
		buf = r_buf_new_with_io (&bin->iob, opt->fd);
	}
	if (!buf) {
		return false;
	}

	if (!opt->sz) {
		opt->sz = r_buf_size (buf);
	}

	// Slice buffer if necessary
	RBuffer *slice = buf;
	if (!is_debugger && (opt->loadaddr != 0 || opt->sz != r_buf_size (buf))) {
		slice = r_buf_new_slice (buf, opt->loadaddr, opt->sz);
	} else if (is_debugger && opt->baseaddr != UT64_MAX) {
		slice = r_buf_new_slice (buf, opt->baseaddr, opt->sz);
	}
	if (slice != buf) {
		r_buf_free (buf);
		buf = slice;
	}
	opt->filename = fname;
	bool res = r_bin_open_buf (bin, buf, opt);
	r_buf_free (buf);
	return res;
}

R_IPI RBinPlugin *r_bin_get_binplugin_by_name(RBin *bin, const char *name) {
	RBinPlugin *plugin;
	RListIter *it;

	r_return_val_if_fail (bin && name, NULL);

	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->meta.name, name)) {
			return plugin;
		}
	}
	return NULL;
}

R_API RBinPlugin *r_bin_get_binplugin_by_buffer(RBin *bin, RBinFile *bf, RBuffer *buf) {
	RBinPlugin *plugin;
	RListIter *it;

	r_return_val_if_fail (bin && buf, NULL);

	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->check) {
			if (plugin->check (bf, buf)) {
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
		if (!strcmp (xtr->meta.name, name)) {
			return xtr;
		}
	}
	return NULL;
}

static void r_bin_plugin_free(RBinPlugin *p) {
	R_FREE (p);
}

// rename to r_bin_plugin_add like the rest
R_API bool r_bin_plugin_add(RBin *bin, RBinPlugin *foo) {
	RListIter *it;
	RBinPlugin *plugin;

	r_return_val_if_fail (bin && foo, false);

	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->meta.name, foo->meta.name)) {
			return false;
		}
	}
	plugin = R_NEW0 (RBinPlugin);
	memcpy (plugin, foo, sizeof (RBinPlugin));
	r_list_append (bin->plugins, plugin);
	return true;
}

R_API bool r_bin_plugin_remove(RBin *bin, RBinPlugin *plugin) {
	// XXX TODO
	return true;
}

R_API bool r_bin_ldr_add(RBin *bin, RBinLdrPlugin *foo) {
	RListIter *it;
	RBinLdrPlugin *ldr;

	r_return_val_if_fail (bin && foo, false);

	// avoid duplicates
	r_list_foreach (bin->binldrs, it, ldr) {
		if (!strcmp (ldr->meta.name, foo->meta.name)) {
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

	// avoid duplicates
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->meta.name, foo->meta.name)) {
			return false;
		}
	}
	r_list_append (bin->binxtrs, foo);
	return true;
}

R_API void r_bin_free(RBin *bin) {
	if (bin) {
		bin->file = NULL;
		free (bin->force);
		free (bin->srcdir);
		free (bin->strenc);
		//r_bin_free_bin_files (bin);
		r_list_free (bin->binfiles);
		r_list_free (bin->binxtrs);
		r_list_free (bin->plugins);
		r_list_free (bin->binldrs);
		sdb_free (bin->sdb);
		r_id_storage_free (bin->ids);
		r_str_constpool_fini (&bin->constpool);
		free (bin);
	}
}

// TODO: this is now a generic function that can reuse RPluginMeta
static bool r_bin_print_plugin_details(RBin *bin, RBinPlugin *bp, PJ *pj, int json) {
	if (json == 'q') {
		bin->cb_printf ("%s\n", bp->meta.name);
	} else if (json) {
		pj_o (pj);
		pj_ks (pj, "name", bp->meta.name);
		pj_ks (pj, "description", bp->meta.desc);
		pj_ks (pj, "license", r_str_get_fail (bp->meta.license, "???"));
		pj_end (pj);
	} else {
		bin->cb_printf ("Name: %s\n", bp->meta.name);
		bin->cb_printf ("Description: %s\n", bp->meta.desc);
		if (bp->meta.license) {
			bin->cb_printf ("License: %s\n", bp->meta.license);
		}
		if (bp->meta.version) {
			bin->cb_printf ("Version: %s\n", bp->meta.version);
		}
		if (bp->meta.author) {
			bin->cb_printf ("Author: %s\n", bp->meta.author);
		}
	}
	return true;
}

// TODO: this is now a generic function that can reuse RPluginMeta
static void __printXtrPluginDetails(RBin *bin, RBinXtrPlugin *bx, int json) {
	if (json == 'q') {
		bin->cb_printf ("%s\n", bx->meta.name);
	} else if (json) {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_o (pj);
		pj_ks (pj, "name", bx->meta.name);
		pj_ks (pj, "description", bx->meta.desc);
		pj_ks (pj, "license", r_str_get_fail (bx->meta.license, "???"));
		pj_end (pj);
		bin->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	} else {
		bin->cb_printf ("Name: %s\n", bx->meta.name);
		bin->cb_printf ("Description: %s\n", bx->meta.desc);
		if (bx->meta.license) {
			bin->cb_printf ("License: %s\n", bx->meta.license);
		}
	}
}

R_API bool r_bin_list_plugin(RBin *bin, const char* name, PJ *pj, int json) {
	RListIter *it;
	RBinPlugin *bp;
	RBinXtrPlugin *bx;

	r_return_val_if_fail (bin && name, false);

	r_list_foreach (bin->plugins, it, bp) {
		if (r_str_startswith (bp->meta.name, name)) {
			continue;
		}
		return r_bin_print_plugin_details (bin, bp, pj, json);
	}
	r_list_foreach (bin->binxtrs, it, bx) {
		if (r_str_startswith (bx->meta.name, name)) {
			continue;
		}
		__printXtrPluginDetails (bin, bx, json);
		return true;
	}

	R_LOG_ERROR ("Cannot find plugin %s", name);
	return false;
}

// TODO: this is now a generic function that can reuse RPluginMeta
R_API void r_bin_list(RBin *bin, PJ *pj, int format) {
	RListIter *it;
	RBinPlugin *bp;
	RBinXtrPlugin *bx;
	RBinLdrPlugin *ld;

	if (format == 'q') {
		r_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf ("%s\n", bp->meta.name);
		}
		r_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf ("%s\n", bx->meta.name);
		}
	} else if (format) {
		pj_o (pj);
		pj_ka (pj, "bin");
		r_list_foreach (bin->plugins, it, bp) {
			pj_o (pj);
			pj_ks (pj, "name", bp->meta.name);
			pj_ks (pj, "description", bp->meta.desc);
			pj_ks (pj, "license", r_str_get_fail (bp->meta.license, "???"));
			pj_end (pj);
		}
		pj_end (pj);
		pj_ka (pj, "xtr");
		r_list_foreach (bin->binxtrs, it, bx) {
			pj_o (pj);
			pj_ks (pj, "name", bx->meta.name);
			pj_ks (pj, "description", bx->meta.desc);
			pj_ks (pj, "license", r_str_get_fail (bx->meta.license, "???"));
			pj_end (pj);
		}
		pj_end (pj);
		pj_ka (pj, "ldr");
		r_list_foreach (bin->binxtrs, it, ld) {
			pj_o (pj);
			pj_ks (pj, "name", ld->meta.name);
			pj_ks (pj, "description", ld->meta.desc);
			pj_ks (pj, "license", r_str_get_fail (ld->meta.license, "???"));
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
	} else {
		r_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf ("bin  %-11s %s (%s) %s %s\n",
				bp->meta.name, bp->meta.desc, r_str_get_fail (bp->meta.license, "???"),
				r_str_get (bp->meta.version),
				r_str_get (bp->meta.author));
		}
		r_list_foreach (bin->binxtrs, it, bx) {
			const char *name = strncmp (bx->meta.name, "xtr.", 4)? bx->meta.name : bx->meta.name + 3;
			bin->cb_printf ("xtr  %-11s %s (%s)\n", name,
				bx->meta.desc, r_str_get_fail (bx->meta.license, "???"));
		}
		r_list_foreach (bin->binldrs, it, ld) {
			const char *name = strncmp (ld->meta.name, "ldr.", 4)? ld->meta.name : ld->meta.name + 3;
			bin->cb_printf ("ldr  %-11s %s (%s)\n", name,
				ld->meta.desc, r_str_get_fail (ld->meta.license, "???"));
		}
	}
}

/* returns the base address of bin or UT64_MAX in case of errors */
R_API ut64 r_bin_get_baddr(RBin *bin) {
	r_return_val_if_fail (bin, UT64_MAX);
	return r_bin_file_get_baddr (bin->cur);
}

/* returns the load address of bin or UT64_MAX in case of errors */
R_API ut64 r_bin_get_laddr(RBin *bin) {
	r_return_val_if_fail (bin, UT64_MAX);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->loadaddr : UT64_MAX;
}

// TODO: should be RBinFile specific imho
R_API void r_bin_set_baddr(RBin *bin, ut64 baddr) {
	r_return_if_fail (bin);
	RBinFile *bf = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	if (o) {
		if (!o->plugin || !o->plugin->baddr) {
			return;
		}
		ut64 file_baddr = o->plugin->baddr (bf);
		if (baddr == UT64_MAX) {
			o->baddr = file_baddr;
			o->baddr_shift = 0; // o->baddr; // - file_baddr;
		} else {
			if (file_baddr != UT64_MAX) {
				o->baddr = baddr;
				o->baddr_shift = baddr - file_baddr;
			}
		}
	} else {
		R_LOG_WARN ("This should be an assert probably");
	}
	// XXX - update all the infos?
	// maybe in RBinFile.rebase() ?
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
R_API const RList *r_bin_get_entries(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->entries : NULL;
}

R_API RList *r_bin_get_fields(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->fields : NULL;
}

R_API const RList *r_bin_get_imports(RBin *bin) {
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

R_API RRBTree *r_bin_patch_relocs(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->rbin, NULL);
	RBinObject *o = r_bin_cur_object (bf->rbin);
	return o? r_bin_object_patch_relocs (bf, o): NULL;
}

R_API RRBTree *r_bin_get_relocs(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->relocs : NULL;
}

R_API RList *r_bin_get_sections(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->sections : NULL;
}

R_API RBinSection *r_bin_get_section_at(RBinObject *o, ut64 off, int va) {
	r_return_val_if_fail (o, NULL);
	RBinSection *section;
	RListIter *iter;
	// TODO: must be O(1) .. use sdb here
	r_list_foreach (o->sections, iter, section) {
		if (section->is_segment) {
			continue;
		}
		ut64 from = va ? o->baddr_shift + section->vaddr : section->paddr;
		ut64 to = from + (va ? section->vsize: section->size);
		if (off >= from && off < to) {
			return section;
		}
	}
	return NULL;
}

R_API RList *r_bin_reset_strings(RBin *bin) {
	RBinFile *bf = r_bin_cur (bin);

	if (!bf || !bf->bo) {
		return NULL;
	}
	if (bf->bo->strings) {
		r_list_free (bf->bo->strings);
		bf->bo->strings = NULL;
	}

	ht_up_free (bf->bo->strings_db);
	bf->bo->strings_db = ht_up_new0 ();

	bf->rawstr = bin->rawstr;
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);

	if (plugin && plugin->strings) {
		bf->bo->strings = plugin->strings (bf);
	} else {
		bf->bo->strings = r_bin_file_get_strings (bf, bin->minstrlen, 0, bf->rawstr);
	}
	if (bin->debase64) {
		r_bin_object_filter_strings (bf->bo);
	}
	return bf->bo->strings;
}

R_API RList *r_bin_get_strings(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->strings : NULL;
}

// TODO: Deprecate because we must use the internal representation
R_API RList *r_bin_get_symbols(RBin *bin) {
	R_LOG_WARN ("Dont use RBin.getSymbols() use getSymbolsVec() instead");
	r_return_val_if_fail (bin, NULL);
	RBinFile *bf = bin->cur;
	return bf? r_bin_file_get_symbols (bf): NULL;
}

R_API RVecRBinSymbol *r_bin_get_symbols_vec(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinFile *bf = bin->cur;
	return bf? r_bin_file_get_symbols_vec (bf): NULL;
}

R_API RList *r_bin_get_mem(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->mem : NULL;
}

// XXX badly designed api, should not exist, aka DEPRECATE
R_API int r_bin_is_big_endian(RBin *bin) {
	r_return_val_if_fail (bin, -1);
	RBinObject *o = r_bin_cur_object (bin);
	return (o && o->info) ? o->info->big_endian : -1;
}

R_API bool r_bin_is_static(RBin *bin) {
	r_return_val_if_fail (bin, false);
	RBinObject *o = r_bin_cur_object (bin);
	if (o && o->libs && r_list_length (o->libs) > 0) {
		return R_BIN_DBG_STATIC & o->info->dbg_info;
	}
	return true;
}

R_API RBin *r_bin_new(void) {
	int i;
	RBinXtrPlugin *static_xtr_plugin;
	RBinLdrPlugin *static_ldr_plugin;
	RBin *bin = R_NEW0 (RBin);
	if (!bin) {
		return NULL;
	}
	if (!r_str_constpool_init (&bin->constpool)) {
		goto trashbin;
	}
	bin->force = NULL;
	bin->filter_rules = UT64_MAX;
	bin->sdb = sdb_new0 ();
	bin->cb_printf = (PrintfCallback)printf;
	bin->plugins = r_list_newf ((RListFree)r_bin_plugin_free);
	bin->minstrlen = 0;
	bin->strpurge = NULL;
	bin->strenc = NULL;
	bin->want_dbginfo = true;
	bin->cur = NULL;
	bin->ids = r_id_storage_new (0, ST32_MAX);

	/* bin parsers */
	bin->binfiles = r_list_newf ((RListFree)r_bin_file_free);
	for (i = 0; bin_static_plugins[i]; i++) {
		r_bin_plugin_add (bin, bin_static_plugins[i]);
	}
	/* extractors */
	bin->binxtrs = r_list_new ();
	if (bin->binxtrs) {
		bin->binxtrs->free = free;
		for (i = 0; bin_xtr_static_plugins[i]; i++) {
			static_xtr_plugin = R_NEW0 (RBinXtrPlugin);
			if (!static_xtr_plugin) {
				goto trashbin_binxtrs;
			}
			*static_xtr_plugin = *bin_xtr_static_plugins[i];
			if (r_bin_xtr_add (bin, static_xtr_plugin) == false) {
				free (static_xtr_plugin);
			}
		}
	}
	/* loaders */
	bin->binldrs = r_list_new ();
	if (bin->binldrs) {
		bin->binldrs->free = free;
		for (i = 0; bin_ldr_static_plugins[i]; i++) {
			static_ldr_plugin = R_NEW0 (RBinLdrPlugin);
			if (!static_ldr_plugin) {
				goto trashbin_binldrs;
			}
			*static_ldr_plugin = *bin_ldr_static_plugins[i];
			if (r_bin_ldr_add (bin, static_ldr_plugin) == false) {
				free (static_ldr_plugin);
			}
		}
	}
	return bin;
trashbin_binldrs:
	r_list_free (bin->binldrs);
trashbin_binxtrs:
	r_list_free (bin->binxtrs);
	r_list_free (bin->binfiles);
	r_id_storage_free (bin->ids);
	r_str_constpool_fini (&bin->constpool);
trashbin:
	free (bin);
	return NULL;
}

R_API bool r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	r_return_val_if_fail (bin && arch, false);

	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits);
	if (!binfile) {
		R_LOG_WARN ("Cannot find binfile with arch/bits %s/%d", arch, bits);
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
		obj = binfile->bo;
	}
	return r_bin_file_set_obj (bin, binfile, obj);
}

R_API bool r_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	r_return_val_if_fail (bin, false);

	if (!arch) {
		return false;
	}
	RBinFile *cur = r_bin_cur (bin);
	RBinObject *obj = NULL;
	name = !name && cur? cur->file: name;
	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits);
	if (binfile && name) {
		obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	}
	return r_bin_file_set_obj (bin, binfile, obj);
}

R_API int r_bin_select_object(RBinFile *binfile, const char *arch, int bits, const char *name) {
	r_return_val_if_fail (binfile, false);
	RBinObject *obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	return r_bin_file_set_obj (binfile->rbin, binfile, obj);
}

// NOTE: this functiona works as expected, but  we need to merge bfid and boid
R_API bool r_bin_select_bfid(RBin *bin, ut32 bf_id) {
	r_return_val_if_fail (bin, false);
	RBinFile *bf = r_bin_file_find_by_id (bin, bf_id);
	return bf? r_bin_file_set_obj (bin, bf, NULL): false;
}

static void list_xtr_archs(RBin *bin, PJ *pj, int mode) {
	RBinFile *binfile = r_bin_cur (bin);
	if (binfile->xtr_data) {
		RListIter *iter_xtr;
		RBinXtrData *xtr_data;
		int bits, i = 0;
		char *arch, *machine;

		if (mode == 'j') {
			pj_ka (pj, "bins");
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
			case 'q': // "iAq"
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j': { // "iAj"
				pj_o (pj);
				pj_ks (pj, "arch", arch);
				pj_ki (pj, "bits", bits);
				pj_kN (pj, "offset", xtr_data->offset);
				pj_kN (pj, "size", xtr_data->size);
				pj_ks (pj, "machine", machine);
				pj_end (pj);
				break;
			}
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
			pj_end (pj);
		}
	}
}

static char *get_arch_string(const char *arch, int bits, RBinInfo *info) {
	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_appendf (sb, "%s_%d", arch, bits);
	if (R_STR_ISNOTEMPTY (info->cpu)) {
		r_strbuf_appendf (sb, " cpu=%s", info->cpu);
	}
	if (R_STR_ISNOTEMPTY (info->abi)) {
		r_strbuf_appendf (sb, " abi=%s", info->abi);
	}
	if (R_STR_ISNOTEMPTY (info->machine)) {
		r_strbuf_appendf (sb, " machine=%s", info->machine);
	}
	return r_strbuf_drain (sb);
}

R_API void r_bin_list_archs(RBin *bin, PJ *pj, int mode) {
	r_return_if_fail (bin);

	char unk[128];
	char archline[256];
	RBinFile *binfile = r_bin_cur (bin);
	const char *name = binfile? binfile->file: NULL;
	int narch = binfile? binfile->narch: 0;

	// r_bin_select (bin, "arm", 64, "arm");
	// are we with xtr format?
	if (binfile && binfile->curxtr) {
		list_xtr_archs (bin, pj, mode);
		return;
	}
	Sdb *binfile_sdb = binfile? binfile->sdb: NULL;
	if (!binfile_sdb) {
	//	R_LOG_ERROR ("Cannot find SDB!");
		return;
	}
	if (!binfile) {
	//	R_LOG_ERROR ("Binary format not currently loaded!");
		return;
	}
	sdb_unset (binfile_sdb, ARCHS_KEY, 0);
	RBinFile *nbinfile = r_bin_file_find_by_name (bin, name);
	if (!nbinfile) {
		return;
	}
	RTable *table = r_table_new ("bins");
	const char *fmt = "dXnss";
	if (mode == 'j') {
		pj_ka (pj, "bins");
	}
	RBinObject *obj = nbinfile->bo;
	RBinInfo *info = obj->info;
	char bits = info? info->bits: 0;
	ut64 boffset = obj->boffset;
	ut64 obj_size = obj->obj_size;
	const char *arch = info? info->arch: NULL;
	const char *machine = info? info->machine: "unknown_machine";
	char * str_fmt;
	if (!arch) {
		snprintf (unk, sizeof (unk), "unk_0");
		arch = unk;
	}
	r_table_hide_header (table);
	r_table_set_columnsf (table, fmt, "num", "offset", "size", "arch", "machine", NULL);

	if (info && narch > 1) {
		switch (mode) {
		case 'q':
			bin->cb_printf ("%s\n", arch);
			break;
		case 'j':
			pj_o (pj);
			pj_ks (pj, "arch", arch);
			pj_ki (pj, "bits", bits);
			pj_kn (pj, "offset", boffset);
			pj_kn (pj, "size", obj_size);
			if (R_STR_ISNOTEMPTY (info->abi)) {
				pj_ks (pj, "abi", info->abi);
			}
			if (!strcmp (arch, "mips")) {
				pj_ks (pj, "isa", info->cpu);
				pj_ks (pj, "flags", info->flags);
			}
			if (machine) {
				pj_ks (pj, "machine", machine);
			}
			pj_end (pj);
			break;
		default:
			str_fmt = get_arch_string (arch, bits, info);
			r_table_add_rowf (table, fmt, 0, boffset, obj_size, str_fmt, machine);
			free (str_fmt);
			char *s = r_table_tostring (table);
			bin->cb_printf ("%s", s);
			free (s);
		}
		snprintf (archline, sizeof (archline) - 1,
			"0x%08" PFMT64x ":%" PFMT64u ":%s:%d:%s",
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
				pj_o (pj);
				pj_ks (pj, "arch", arch);
				pj_ki (pj, "bits", bits);
				pj_kn (pj, "offset", boffset);
				pj_kn (pj, "size", obj_size);
				if (R_STR_ISNOTEMPTY (info->abi)) {
					pj_ks (pj, "abi", info->abi);
				}
				if (!strcmp (arch, "mips")) {
					pj_ks (pj, "isa", info->cpu);
					pj_ks (pj, "flags", info->flags);
				}
				if (machine) {
					pj_ks (pj, "machine", machine);
				}
				pj_end (pj);
				break;
			default:
				str_fmt = get_arch_string (arch, bits, info);
				r_table_add_rowf (table, fmt, 0, boffset, obj_size, str_fmt, "");
				free (str_fmt);
				char *s = r_table_tostring (table);
				bin->cb_printf ("%s", s);
				free (s);
			}
			snprintf (archline, sizeof (archline),
				"0x%08" PFMT64x ":%" PFMT64u ":%s:%d",
				boffset, obj_size, arch, bits);
		} else if (nbinfile && mode) {
			switch (mode) {
			case 'q':
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j':
				pj_o (pj);
				pj_ks (pj, "arch", arch);
				pj_ki (pj, "bits", bits);
				pj_kn (pj, "offset", boffset);
				pj_kn (pj, "size", obj_size);
				if (machine) {
					pj_ks (pj, "machine", machine);
				}
				pj_end (pj);
				break;
			default:
				r_table_add_rowf (table, fmt, 0, boffset, obj_size, "", "");
				char *s = r_table_tostring (table);
				bin->cb_printf ("%s", s);
				free (s);
			}
			snprintf (archline, sizeof (archline),
				"0x%08" PFMT64x ":%" PFMT64u ":%s:%d",
				boffset, obj_size, "unk", 0);
		} else {
			R_LOG_ERROR ("Invalid RBinFile");
		}
		//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
	}
	if (mode == 'j') {
		pj_end (pj);
	}
	r_table_free (table);
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static RBinSection* __get_vsection_at(RBin *bin, ut64 vaddr) {
	r_return_val_if_fail (bin, NULL);
	if (!bin->cur || !bin->cur->bo) {
		return NULL;
	}
	return r_bin_get_section_at (bin->cur->bo, vaddr, true);
}

R_API void r_bin_bind(RBin *bin, RBinBind *b) {
	if (b) {
		b->bin = bin;
		b->get_offset = __getoffset;
		b->get_name = __getname;
		b->get_sections = r_bin_get_sections;
		b->get_vsect_at = __get_vsection_at;
		b->demangle = r_bin_demangle;
	}
}

R_API RBuffer *r_bin_create(RBin *bin, const char *p,
	const ut8 *code, int codelen,
	const ut8 *data, int datalen,
	RBinArchOptions *opt) {

	r_return_val_if_fail (bin && p && opt, NULL);

	RBinPlugin *plugin = r_bin_get_binplugin_by_name (bin, p);
	if (!plugin) {
		R_LOG_WARN ("Cannot find RBin plugin named '%s'", p);
		return NULL;
	}
	if (!plugin->create) {
		R_LOG_WARN ("RBin plugin '%s' does not implement \"create\" method", p);
		return NULL;
	}
	codelen = R_MAX (codelen, 0);
	datalen = R_MAX (datalen, 0);
	return plugin->create (bin, code, codelen, data, datalen, opt);
}

R_API RBuffer *r_bin_package(RBin *bin, const char *type, const char *file, RList *files) {
	if (!strcmp (type, "zip")) {
		// XXX: implement me
		r_warn_if_reached ();
	} else if (!strcmp (type, "fat")) {
		// XXX: this should be implemented in the fat plugin, not here
		// XXX should pick the callback from the plugin list
		const char *f;
		RListIter *iter;
		ut32 num;
		ut8 *num8 = (ut8*)&num;
		RBuffer *buf = r_buf_new_file (file, O_RDWR | O_CREAT, 0644);
		if (!buf) {
			R_LOG_ERROR ("Cannot open file %s - Permission Denied", file);
			return NULL;
		}
		r_buf_write_at (buf, 0, (const ut8*)"\xca\xfe\xba\xbe", 4);
		int count = r_list_length (files);

		num = r_read_be32 (&count);
		ut64 from = 0x1000;
		r_buf_write_at (buf, 4, num8, 4);
		int off = 12;
		r_list_foreach (files, iter, f) {
			size_t f_len = 0;
			ut8 *f_buf = (ut8 *)r_file_slurp (f, &f_len);
			if (!f_buf) {
				R_LOG_ERROR ("Cannot open %s", f);
				free (f_buf);
				continue;
			}
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
		R_LOG_ERROR ("Use `rabin2 -X [fat|zip] [filename] [files ...]`");
	}
	return NULL;
}

R_API RList */*<RBinClass>*/ r_bin_get_classes(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->classes : NULL;
}

/* returns vaddr, rebased with the baseaddr of bin, if va is enabled for bin,
 * paddr otherwise */
R_API ut64 r_bin_get_vaddr(RBin *bin, ut64 paddr, ut64 vaddr) {
	r_return_val_if_fail (bin && paddr != UT64_MAX, UT64_MAX);

	if (!bin->cur) {
		return paddr;
	}
	/* hack to realign thumb symbols */
	if (bin->cur->bo && bin->cur->bo->info && bin->cur->bo->info->arch) {
		if (bin->cur->bo->info->bits == 16) {
			RBinSection *s = r_bin_get_section_at (bin->cur->bo, paddr, false);
			// autodetect thumb
			if (s && (s->perm & R_PERM_X) && strstr (s->name, "text")) {
				if (!strcmp (bin->cur->bo->info->arch, "arm") && (vaddr & 1)) {
					vaddr = (vaddr >> 1) << 1;
				}
			}
		}
	}
	return r_bin_file_get_vaddr (bin->cur, paddr, vaddr);
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
	RBinFile *bf = r_bin_cur (bin);
	return bf ? bf->bo : NULL;
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
R_API RBinField *r_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format, bool format_named) {
	RBinField *ptr = R_NEW0 (RBinField);
	if (ptr) {
		ptr->name = strdup (name);
		ptr->comment = (comment && *comment)? strdup (comment): NULL;
		ptr->format = (format && *format)? strdup (format): NULL;
		ptr->format_named = format_named;
		ptr->paddr = paddr;
		ptr->size = size;
	//	ptr->visibility = any default visibility?
		ptr->vaddr = vaddr;
	}
	return ptr;
}

// use void* to honor the RListFree signature
R_API void r_bin_field_free(void *_field) {
	RBinField *field = (RBinField*) _field;
	if (field) {
		free (field->name);
		free (field->comment);
		free (field->format);
		free (field);
	}
}

// method name too long
// RBin.methFlagToString(RBin.Method.CLASS)
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

R_IPI RBinSection *r_bin_section_new(const char *name) {
	RBinSection *s = R_NEW0 (RBinSection);
	if (s) {
		s->name = name? strdup (name): NULL;
	}
	return s;
}

R_API RBinSection *r_bin_section_clone(RBinSection *s) {
	RBinSection *d = R_NEW0 (RBinSection);
	if (d) {
		memcpy (d, s, sizeof (RBinSection));
		d->name = s->name? strdup (s->name): NULL;
		d->format = s->format? strdup (s->format): NULL;
	}
	return d;
}

R_IPI void r_bin_section_free(RBinSection *bs) {
	if (bs) {
		free (bs->name);
		free (bs->format);
		free (bs);
	}
}

R_API RBinFile *r_bin_file_at(RBin *bin, ut64 at) {
	RListIter *it, *it2;
	RBinFile *bf;
	RBinSection *s;
	r_list_foreach (bin->binfiles, it, bf) {
		// chk for baddr + size of no section is covering anything
		// we should honor maps not sections imho
		r_list_foreach (bf->bo->sections, it2, s) {
			if (at >= s->vaddr  && at < (s->vaddr + s->vsize)) {
				return bf;
			}
		}
		if (at >= bf->bo->baddr && at < (bf->bo->baddr + bf->size)) {
			return bf;
		}
	}
	return NULL;
}

R_API RBinTrycatch *r_bin_trycatch_new(ut64 source, ut64 from, ut64 to, ut64 handler, ut64 filter) {
	RBinTrycatch *tc = R_NEW0 (RBinTrycatch);
	if (tc) {
		tc->source = source;
		tc->from = from;
		tc->to = to;
		tc->handler = handler;
		tc->filter = filter;
	}
	return tc;
}

R_API void r_bin_trycatch_free(RBinTrycatch *tc) {
	free (tc);
}
