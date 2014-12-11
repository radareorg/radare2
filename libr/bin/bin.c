/* radare - LGPL - Copyright 2009-2014 - pancake, nibble, dso */

// TODO: dlopen library and show address

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_list.h>
#include <r_bin.h>
#include <r_io.h>
#include <list.h>
#include "../config.h"

R_LIB_VERSION(r_bin);

#define DB a->sdb;
#define RBINLISTFREE(x) if(x){r_list_free(x);x=NULL;}

#define ARCHS_KEY "archs"

static RBinPlugin *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS };
static RBinXtrPlugin *bin_xtr_static_plugins[] = { R_BIN_XTR_STATIC_PLUGINS };

static int is_data_section(RBinFile *a, RBinSection *s);
static RList* get_strings(RBinFile *a, int min, int dump);
static void r_bin_object_delete_items (RBinObject *o);
static void r_bin_object_free (void /*RBinObject*/ *o_);
static int r_bin_object_set_items(RBinFile *binfile, RBinObject *o);
static int r_bin_file_set_bytes (RBinFile *binfile, const ut8 * bytes, ut64 sz);
//static int remove_bin_file_by_binfile (RBin *bin, RBinFile * binfile);
//static void r_bin_free_bin_files (RBin *bin);
static void r_bin_file_free (void /*RBinFile*/ *bf_);
static RBinFile * r_bin_file_create_append (RBin *bin, const char *file, const ut8 * bytes, ut64 sz, ut64 file_sz, int rawstr, int fd, const char *xtrname);

static int r_bin_file_object_new_from_xtr_data (RBin *bin, RBinFile *bf, ut64 baseaddr, ut64 loadaddr, RBinXtrData *xtr_data);
static int r_bin_files_populate_from_xtrlist (RBin *bin, RBinFile *binfile, ut64 baseaddr, ut64 loadaddr, RList *xtr_data_list);
static RBinFile * r_bin_file_xtr_load_bytes (RBin *bin, RBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
int r_bin_load_io_at_offset_as_sz(RBin *bin, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int xtr_idx, ut64 offset, const char *name, ut64 sz);

static RBinPlugin * r_bin_get_binplugin_by_name (RBin *bin, const char *name);
static RBinXtrPlugin * r_bin_get_xtrplugin_by_name (RBin *bin, const char *name);
static RBinPlugin * r_bin_get_binplugin_any (RBin *bin);
static RBinObject * r_bin_object_new (RBinFile *binfile, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz);
static RBinFile * r_bin_file_new (RBin *bin, const char *file, const ut8 * bytes, ut64 sz, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb);
static RBinFile * r_bin_file_new_from_bytes (RBin *bin, const char *file, const ut8 * bytes, ut64 sz, ut64 file_sz, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname, const char *xtrname, ut64 offset);
static int getoffset (RBin *bin, int type, int idx);
static const char *getname (RBin *bin, int off);
static int r_bin_file_object_add (RBinFile *binfile, RBinObject *o);

R_API void r_bin_iobind(RBin *bin, RIO *io) {
	r_io_bind (io, &bin->iob);
}

// TODO: move these two function do a different file
R_API RBinXtrData * r_bin_xtrdata_new (void *xtr_obj, FREE_XTR free_xtr, RBuffer *buf, ut64 offset, ut64 size, ut32 file_count) {
	RBinXtrData *data = NULL;
	RBuffer *tb = buf ? r_buf_new () : NULL;
	if (!tb) return data;
	if (!r_buf_append_buf (tb, buf)) {
		r_buf_free (tb);
		return data;
	}
	data = R_NEW0 (RBinXtrData);
	data->xtr_obj = xtr_obj;
	data->free_xtr = free_xtr;
	data->buf = tb;
	data->offset = offset;
	data->size = size;
	data->file_count = file_count;
	return data;
}

R_API void r_bin_xtrdata_free (void /*RBinXtrData*/ *data_) {
	RBinXtrData *data = data_;
	if (data) {
		if (data->free_xtr) data->free_xtr (data->xtr_obj);
		free (data->file);
		r_buf_free (data->buf);
		free (data);
	}
}

R_API RBinObject * r_bin_file_object_get_cur (RBinFile *binfile) {
	return binfile ? binfile->o : NULL;
}

R_API RBinObject * r_bin_object_get_cur (RBin *bin) {
	if (!bin) return NULL;
	return r_bin_file_object_get_cur (r_bin_cur (bin));
}

R_API RBinPlugin * r_bin_file_cur_plugin (RBinFile *binfile) {
	return binfile && binfile->o ? binfile->o->plugin : NULL;
}

R_API int r_bin_file_cur_set_plugin (RBinFile *binfile, RBinPlugin *plugin) {
	if (binfile && binfile->o) {
		binfile->o->plugin = plugin;
		return R_TRUE;
	}
	return R_FALSE;
}

enum {
	R_STRING_TYPE_DETECT = '?',
	R_STRING_TYPE_ASCII = 'a',
	R_STRING_TYPE_UTF8 = 'u',
	R_STRING_TYPE_WIDE = 'w',
};

#define R_STRING_SCAN_BUFFER_SIZE 2048

static int string_scan_range (RList *list, const ut8 *buf, int min, const ut64 from, const ut64 to, int type) {
	ut8 tmp[R_STRING_SCAN_BUFFER_SIZE];
	ut64 needle = from, str_start;
	int count = 0, i, rc, runes, str_type = R_STRING_TYPE_DETECT;
	if (type == -1)
		type = R_STRING_TYPE_DETECT;

	if (!buf || !min)
		return -1;

	while (needle < to) {
		rc = r_utf8_decode (buf+needle, to-needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}

		str_type = type;

		if (str_type == R_STRING_TYPE_DETECT) {
			if (needle+rc+2 < to &&
				buf[needle+rc+0] == 0x00 &&
				buf[needle+rc+1] != 0x00 &&
				buf[needle+rc+2] == 0x00)
				str_type = R_STRING_TYPE_WIDE;
			else
				str_type = R_STRING_TYPE_ASCII;
		}

		runes = 0;
		str_start = needle;

		/* Eat a whole C string */
		for (rc = i = 0; i < sizeof (tmp) - 3 && needle < to; i += rc) {
			RRune r;

			if (str_type == R_STRING_TYPE_WIDE) {
				if (needle+1<to) {
					r = buf[needle+1] << 8 | buf[needle];
					rc = 2;
				} else {
					break;
				}
			} else {
				rc = r_utf8_decode (buf+needle, to-needle, &r);
				if (rc > 1) str_type = R_STRING_TYPE_UTF8;
			}

			/* Invalid sequence detected */
			if (!rc) {
				needle++;
				break;
			}

			needle += rc;

			if (r_isprint (r)) {
				rc = r_utf8_encode (&tmp[i], r);
				runes++;
			}
			/* Print the escape code */
			else if (r && r < 0x100 && strchr ("\b\v\f\n\r\t\a\e", (char)r)) {
				tmp[i+0] = '\\';
				tmp[i+1] = "       abtnvfr             e"[r];
				rc = 2;
				runes++;
			}
			/* \0 marks the end of C-strings */
			else break;
		}

		tmp[i++] = '\0';

		if (runes >= min) {
			if (list) {
				RBinString *new = R_NEW0 (RBinString);
				new->type = str_type;
				new->length = runes;
				new->size = needle - str_start;
				new->ordinal = count++;
				new->paddr = new->vaddr = str_start;
				if (i < sizeof (new->string))
					memcpy (new->string, tmp, i);
				r_list_append (list, new);
			} else {
				// DUMP TO STDOUT. raw dumping for rabin2 -zzz
				printf ("0x%08"PFMT64x" %s\n", str_start, tmp);
			}
		}
	}

	return count;
}

static void get_strings_range(RBinFile *arch, RList *list, int min, ut64 from, ut64 to) {
	RBinPlugin *plugin = r_bin_file_cur_plugin (arch);
	RBinString *ptr;
	RListIter *it;

	if (!arch || !arch->buf || !arch->buf->buf)
		return;

	if (!arch->rawstr)
		if (!plugin || !plugin->info)
			return;
	if (min == 0)
		min = plugin? plugin->minstrlen: 4;

#if 0
	if (arch->rawstr == R_TRUE)
		min = 1;
#endif

	/* Some plugins return zero, fix it up */
	if (min == 0)
		min = 4;
	if (min < 0)
		return;

	if (!to || to > arch->buf->length)
		to = arch->buf->length;

	if (arch->rawstr != 2) {
		// in case of dump ignore here
		if (to != 0 && to > 0xf00000) {
			eprintf ("WARNING: bin_strings buffer is too big (0x%08"PFMT64x")\n", to-from);
			return;
		}
	}

	if (string_scan_range (list, arch->buf->buf, min, from, to, -1) < 0)
		return;

	r_list_foreach (list, it, ptr) {
		RBinSection *s = r_bin_get_section_at (arch->o, ptr->paddr, R_FALSE);
		if (s) ptr->vaddr = s->vaddr + (ptr->paddr - s->paddr);
	}
}

static int is_data_section(RBinFile *a, RBinSection *s) {
	RBinObject *o = a->o;
	if (o && o->info && o->info->bclass) {
		if (strstr (o->info->bclass, "MACH0") && strstr (s->name, "_cstring")) // OSX
			return 1;
		if (strstr (o->info->bclass, "ELF") && strstr (s->name, "data") && !strstr (s->name, "rel")) // LINUX
			return 1;
#define X 1
#define ROW (4|2)
		if (strstr (o->info->bclass, "PE") && s->srwx & ROW && !(s->srwx&X) && s->size>0 ) {
			if (!strcmp (s->name, ".rdata")) // Maybe other sections are interesting too?
				return 1;
		}
	}
	if (strstr (s->name, "_const")) // Rust
		return 1;
	return 0;
}

static RList* get_strings(RBinFile *a, int min, int dump) {
	RListIter *iter;
	RBinSection *section;
	RBinObject *o = a? a->o : NULL;
	RList *ret;
	if (!o) return NULL;
	if (dump) {
		/* dump to stdout, not stored in list */
		ret = NULL;
	} else {
		ret = r_list_newf (free);
		if (!ret) return NULL;
	}

	if (o->sections && !r_list_empty (o->sections) && !a->rawstr) {
		r_list_foreach (o->sections, iter, section) {
			if (is_data_section (a, section)) {
				get_strings_range (a, ret, min,
					section->paddr,
					section->paddr+section->size);
			}
		}
	} else {
		get_strings_range (a, ret, min, 0, a->size);
	}
	return ret;
}

R_API int r_bin_dump_strings(RBinFile *a, int min) {
	get_strings (a, min, 1);
	return 0;
}

R_API int r_bin_load_languages(RBinFile *binfile) {
	if (r_bin_lang_objc (binfile))
		return R_BIN_NM_OBJC;
	if (r_bin_lang_cxx (binfile))
		return R_BIN_NM_CXX;
	return R_BIN_NM_NONE;
}

static void r_bin_object_delete_items (RBinObject *o) {
	ut32 i = 0;
	if (!o) return;
	r_list_free (o->entries);
	r_list_free (o->fields);
	r_list_free (o->imports);
	r_list_free (o->libs);
	r_list_free (o->relocs);
	r_list_free (o->sections);
	r_list_free (o->strings);
	r_list_free (o->symbols);
	r_list_free (o->classes);
	r_list_free (o->lines);

	o->entries = NULL;
	o->fields = NULL;
	o->imports = NULL;
	o->libs = NULL;
	o->relocs = NULL;
	o->sections = NULL;
	o->strings = NULL;
	o->symbols = NULL;
	o->classes = NULL;
	o->lines = NULL;
	o->info = NULL;
	for (i=0; i<R_BIN_SYM_LAST; i++){
		free (o->binsym[i]);
		o->binsym[i] = NULL;
	}
}

static void r_bin_object_free (void /*RBinObject*/ *o_) {
	RBinObject* o = o_;
	if (!o) return;
	r_bin_object_delete_items (o);
	free (o);
}
// XXX - change this to RBinObject instead of RBinFile
// makes no sense to pass in a binfile and set the RBinObject
// kinda a clunky functions
static int r_bin_object_set_items(RBinFile *binfile, RBinObject *o) {
	RBinObject *old_o = binfile ? binfile->o : NULL;
	int i, minlen;
	RBinPlugin *cp = NULL;
	if (!binfile || !o || !o->plugin) return R_FALSE;

	cp = o->plugin;
	if (binfile->rbin->minstrlen>0) {
		minlen = binfile->rbin->minstrlen;
	} else {
		minlen = cp->minstrlen;
	}
	binfile->o = o;
	if (cp->baddr) o->baddr = cp->baddr (binfile);
	o->loadaddr = o->baddr;
	if (cp->boffset) o->boffset = cp->boffset (binfile);
	// XXX: no way to get info from xtr pluginz?
	// Note, object size can not be set from here due to potential inconsistencies
	if (cp->size)
		o->size = cp->size (binfile);
	if (cp->binsym)
		for (i=0; i<R_BIN_SYM_LAST; i++)
			o->binsym[i] = cp->binsym (binfile, i);
	if (cp->entries) o->entries = cp->entries (binfile);
	if (cp->fields) o->fields = cp->fields (binfile);
	if (cp->imports) o->imports = cp->imports (binfile);
	o->info = cp->info? cp->info (binfile): NULL;
	if (cp->libs) o->libs = cp->libs (binfile);
	if (cp->symbols) o->symbols = cp->symbols (binfile);
	if (cp->relocs) o->relocs = cp->relocs (binfile);
	if (cp->sections) o->sections = cp->sections (binfile);
	if (cp->strings) o->strings = cp->strings (binfile);
	else o->strings = get_strings (binfile, minlen, 0);
	if (cp->classes) o->classes = cp->classes (binfile);
	if (cp->lines) o->lines = cp->lines (binfile);
	if (cp->get_sdb) o->kv = cp->get_sdb (o);
	o->lang = r_bin_load_languages (binfile);
	binfile->o = old_o;
	return R_TRUE;
}

// XXX - this is a rather hacky way to do things, there may need to be a better way.
R_API int r_bin_load(RBin *bin, const char *file, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd, int rawstr) {
// ALIAS?	return r_bin_load_as (bin, file, baseaddr, loadaddr, xtr_idx, fd, rawstr, 0, file);
	RIOBind *iob = &(bin->iob);
	RIO *io;
	RIODesc *desc = NULL;
	io = (iob&&iob->get_io) ? iob->get_io(iob) : NULL;
	if (!io) return R_FALSE;
	bin->rawstr = rawstr;
	desc = fd == -1 ? iob->desc_open (io, file, O_RDONLY, 0644) : iob->desc_get_by_fd (io, fd);
	if (!desc) return R_FALSE;
	return r_bin_load_io (bin, desc, baseaddr, loadaddr, xtr_idx);
}

R_API int r_bin_load_as(RBin *bin, const char *file, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd, int rawstr, int fileoffset, const char *name) {
	RIOBind *iob = &(bin->iob);
	RIO *io = iob ? iob->get_io(iob) : NULL;
	RIODesc *desc = NULL;
	if (!io) return R_FALSE;

	desc = fd == -1 ?
		iob->desc_open (io, file, O_RDONLY, 0644) :
		iob->desc_get_by_fd (io, fd);
	if (!desc) return R_FALSE;
	return r_bin_load_io_at_offset_as (bin, desc, baseaddr,
		loadaddr, xtr_idx, fileoffset, name);
}

R_API int r_bin_reload(RBin *bin, RIODesc *desc, ut64 baseaddr) {
	RIOBind *iob = &(bin->iob);
	RIO *io = iob ? iob->get_io(iob) : NULL;
	RBinFile *bf = NULL;
	ut8* buf_bytes = NULL;
	ut64 len_bytes = UT64_MAX, sz = UT64_MAX;

	if (!io) return R_FALSE;
	RList *the_obj_list;
	int res = R_FALSE;

	if (!desc || !io) return R_FALSE;

	bf = r_bin_file_find_by_name (bin, desc->name);
	if (!bf) return R_FALSE;

	the_obj_list = bf->objs;
	bf->objs = r_list_newf ((RListFree)r_bin_object_free);
	// invalidate current object reference
	bf->o = NULL;

	// XXX - this needs to be reimplemented to account for 
	// performance impacts.
	buf_bytes = NULL;

	sz = iob->desc_size (io, desc);
	if (sz == UT64_MAX && desc->plugin && desc->plugin->isdbg) {
		// attempt a local open and read
		// This happens when a plugin like debugger does not have a fixed size.
		// if there is no fixed size or its MAXED, there is no way to definitively
		// load the bin-properly.  Many of the plugins require all content and are not
		// stream based loaders
		RIODesc *tdesc = iob->desc_open (io, desc->name, desc->flags, R_IO_READ);
		if (!tdesc) return R_FALSE;
		sz = iob->desc_size (io, tdesc);
		if (sz == UT64_MAX) {
			iob->desc_close (io, tdesc);
			return R_FALSE;
		}
		buf_bytes = iob->desc_read (io, tdesc, &len_bytes);
		iob->desc_close (io, tdesc);
	} else if (sz == UT64_MAX || sz>(64*1024*1024)) {// too big, probably wrong
		return R_FALSE;
	} else {
		buf_bytes = iob->desc_read (io, desc, &len_bytes);
	}

	buf_bytes = iob->desc_read (io, desc, &sz);
	if (!buf_bytes) {
		free (buf_bytes);
		return R_FALSE;
	}

	r_bin_file_set_bytes (bf, buf_bytes, sz);
	free (buf_bytes);

	if (r_list_length (the_obj_list) == 1) {
		RBinObject *old_o = (RBinObject *) r_list_get_n (the_obj_list, 0);

		res = r_bin_load_io_at_offset_as (bin, desc, baseaddr,
				old_o->loadaddr, 0, old_o->boffset, NULL);
	} else {
		RListIter *iter = NULL;
		RBinObject *old_o;
		r_list_foreach (the_obj_list, iter, old_o) {
			// XXX - naive. do we need a way to prevent multiple "anys" from being opened?
			res = r_bin_load_io_at_offset_as (bin, desc, baseaddr, old_o->loadaddr, 0, old_o->boffset, old_o->plugin->name);
		}
	}
	bf->o = r_list_get_n (bf->objs, 0);
	r_list_free (the_obj_list);
	return res;
}

R_API int r_bin_load_io(RBin *bin, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int xtr_idx) {
	return r_bin_load_io_at_offset_as (bin, desc, baseaddr, loadaddr, xtr_idx, 0, NULL);
}

R_API int r_bin_load_io_at_offset_as_sz(RBin *bin, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int xtr_idx, ut64 offset, const char *name, ut64 sz) {
	RIOBind *iob = &(bin->iob);
	RIO *io = iob ? iob->get_io(iob) : NULL;
	RListIter *it;
	ut8* buf_bytes;
	RBinXtrPlugin *xtr;
	ut64 file_sz = UT64_MAX;
	RBinFile *binfile = NULL;
	ut8 is_debugger = desc && desc->plugin && desc->plugin->isdbg;

	if (!io || !desc) return R_FALSE;

	buf_bytes = NULL;
	file_sz = iob->desc_size (io, desc);
	if ((file_sz == 0 || file_sz == UT64_MAX) && is_debugger) {
		int fail = 1;
		/* get file path from desc name */
		/* - asume path+exec have no space in path */
		char *filepath, *foo = strdup (desc->name);
		filepath = strchr (foo, ' ');
		if (filepath) *filepath = 0;
		filepath = r_file_path (foo);

		// attempt a local open and read
		// This happens when a plugin like debugger does not have a fixed size.
		// if there is no fixed size or its MAXED, there is no way to definitively
		// load the bin-properly.  Many of the plugins require all content and are not
		// stream based loaders
		// NOTE: For RBin we dont need to open the file in read-write. This can be problematic
		RIODesc *tdesc = iob->desc_open (io, filepath, R_IO_READ, 0); //desc->flags, R_IO_READ);
		if (tdesc) {
			file_sz = iob->desc_size (io, tdesc);
			if (file_sz != UT64_MAX) {
				sz = R_MIN (file_sz, sz);
				buf_bytes = iob->desc_read (io, tdesc, &sz);
				fail = 0;
			}
			iob->desc_close (io, tdesc);
		}
		free (foo);
		free (filepath);
		if (fail)
			return R_FALSE;
	} else if (sz != UT64_MAX) {
		sz = R_MIN (file_sz, sz);
		buf_bytes = iob->desc_read (io, desc, &sz);
	} else {
		return R_FALSE;
	}

	if (!name) {
		// XXX - for the time being this is fine, but we may want to change the name to something like
		// <xtr_name>:<bin_type_name>
		r_list_foreach (bin->binxtrs, it, xtr) {
			if (xtr->check && xtr->check_bytes (buf_bytes, sz)) {
				if (xtr && (xtr->extract_from_bytes || xtr->extractall_from_bytes)) {
					if (is_debugger && sz != file_sz) {
						free (buf_bytes);
						RIODesc *tdesc = iob->desc_open (io, desc->name, desc->flags, R_IO_READ);
						if (!tdesc) return R_FALSE;
						sz = iob->desc_size (io, tdesc);
						if (sz == UT64_MAX) {
							iob->desc_close (io, tdesc);
							return R_FALSE;
						}
						buf_bytes = iob->desc_read (io, tdesc, &sz);
						iob->desc_close (io, tdesc);
					} else if (sz != file_sz) {
						free (buf_bytes);
						buf_bytes = iob->desc_read (io, desc, &sz);
					}

					binfile = r_bin_file_xtr_load_bytes (bin, xtr,
						desc->name, buf_bytes, sz, file_sz,
						baseaddr, loadaddr, xtr_idx,
						desc->fd, bin->rawstr);
				}
				xtr = NULL;
			}
		}
	}

	if (!binfile) {
		binfile = r_bin_file_new_from_bytes (bin, desc->name,
			buf_bytes, sz, file_sz, bin->rawstr, baseaddr, loadaddr,
			desc->fd, name, NULL, offset);
	}

	if (binfile) return r_bin_file_set_cur_binfile (bin, binfile);
	return R_FALSE;
}

R_API int r_bin_load_io_at_offset_as(RBin *bin, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int xtr_idx, ut64 offset, const char *name) {
#if 1
	// adding file_sz to help reduce the performance impact on the system
	// in this case the number of bytes read will be limited to 2MB (MIN_LOAD_SIZE)
	// if it fails, the whole file is loaded.
	const ut64 MAX_LOAD_SIZE = 128 * (1 << 10 << 10);
	int res = r_bin_load_io_at_offset_as_sz (bin, desc, baseaddr,
		loadaddr, xtr_idx, offset, name, MAX_LOAD_SIZE);
	if (res)
		return res;
#endif
	return r_bin_load_io_at_offset_as_sz (bin, desc, baseaddr,
		loadaddr, xtr_idx, offset, name, UT64_MAX);
}

#if 0
static int remove_bin_file_by_binfile (RBin *bin, RBinFile * binfile) {
	RListIter *iter;
	RBinFile *tmp_binfile = NULL;
	int found_bin = R_FALSE;
	r_list_foreach (bin->binfiles, iter, tmp_binfile) {
		if (tmp_binfile == binfile) {
			r_list_delete (bin->binfiles, iter);
			found_bin = R_TRUE;
			break;
		}
	}
	return found_bin;
}

static void r_bin_free_bin_files (RBin *bin) {
	RListIter *iter, *t_iter;
	RBinFile *a;
	r_list_foreach_safe (bin->binfiles, iter, t_iter, a) {
		r_bin_file_free (a);
		r_list_delete(bin->binfiles,iter);
	}
}
#endif


R_API int r_bin_file_deref_by_bind (RBinBind * binb) {
	RBin *bin = binb ? binb->bin : NULL;
	RBinFile *a = r_bin_cur (bin);
	return r_bin_file_deref (bin, a);
}

R_API int r_bin_file_deref (RBin *bin, RBinFile * a) {
	RBinObject *o = r_bin_cur_object (bin);
	int res = R_FALSE;
	if (a && !o) {
		//r_list_delete_data (bin->binfiles, a);
		res = R_TRUE;
	} else if (a && o->referenced-1 < 1) {
		//r_list_delete_data (bin->binfiles, a);
		res = R_TRUE;
	// not thread safe
	} else if (o) o->referenced--;
	// it is possible for a file not
	// to be bound to RBin and RBinFiles
	// XXX - is this an ok assumption?
	if (bin) bin->cur = NULL;
	return res;
}

R_API int r_bin_file_ref_by_bind (RBinBind * binb) {
	RBin *bin = binb ? binb->bin : NULL;
	RBinFile *a = r_bin_cur (bin);
	return r_bin_file_ref (bin, a);
}

R_API int r_bin_file_ref (RBin *bin, RBinFile * a) {
	RBinObject *o = r_bin_cur_object (bin);
	int res = R_FALSE;
	if (!a) return R_FALSE;
	if (o) {
		o->referenced--;
		res = R_TRUE;
	}
	return res;
}

static void r_bin_file_free (void /*RBinFile*/ *bf_) {
	RBinFile* a = bf_;
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);

	if (!a) return;

	// Binary format objects are connected to the
	// RBinObject, so the plugin must destroy the
	// format data first
	if (plugin && plugin->destroy)
		plugin->destroy (a);

	if (a->curxtr && a->curxtr->destroy)
		a->curxtr->free_xtr ((void *) (a->xtr_obj));

	r_buf_free (a->buf);
	// TODO: unset related sdb namespaces
	if (a && a->sdb_addrinfo) {
		sdb_free (a->sdb_addrinfo);
		a->sdb_addrinfo = NULL;
	}
	free (a->file);
	r_list_free (a->objs);
	memset (a, 0, sizeof (RBinFile));
}

static int r_bin_file_object_add (RBinFile *binfile, RBinObject *o) {
	if (!o) return R_FALSE;
	r_list_append (binfile->objs, o);
	r_bin_file_set_cur_binfile_obj (binfile->rbin, binfile, o);
	return R_TRUE;
}

static RBinFile * r_bin_file_create_append (RBin *bin, const char *file, const ut8 * bytes, ut64 sz, ut64 file_sz, int rawstr, int fd, const char *xtrname) {
	RBinFile *bf = NULL;
	bf = r_bin_file_new (bin, file, bytes, sz, file_sz, rawstr, fd, xtrname, bin->sdb);
	if (bf) r_list_append (bin->binfiles, bf);
	return bf;
}

static int r_bin_files_populate_from_xtrlist (RBin *bin, RBinFile *binfile, ut64 baseaddr, ut64 loadaddr, RList *xtr_data_list) {
	RListIter *iter = NULL;
	RBinXtrData *data = NULL;
	int res = R_TRUE;
	r_list_foreach (xtr_data_list, iter, data) {
		res = r_bin_file_object_new_from_xtr_data  (bin, binfile, baseaddr, loadaddr, data);
		if (!res) break;
	}
	return res;
}

static RBinFile * r_bin_file_xtr_load_bytes (RBin *bin, RBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr) {
	RBinFile * bf = bin? r_bin_file_find_by_name (bin, filename) : NULL;
	if (!bf) {
		if (!bin) return NULL;
		bf = r_bin_file_create_append (bin, filename, bytes, sz, file_sz, rawstr, fd, xtr->name);
		if (!bf) return bf;
	}
	if (idx == 0 && xtr && bytes) {
		RList *xtr_data_list = xtr->extractall_from_bytes (bytes, sz);
		if (xtr_data_list){
			if (!r_bin_files_populate_from_xtrlist (bin, bf, baseaddr, loadaddr, xtr_data_list))
				eprintf ("Error: failed to load the Extracted Objects with %s for %s.", xtr->name, bf->file);
		}
		r_list_free (xtr_data_list);
	} else if (xtr && xtr->extract_from_bytes) {
		if (idx == 0) idx = 1;
		RBinXtrData *xtr_data = xtr->extract_from_bytes (bytes, sz, idx);
		if (xtr_data){
			if (r_bin_file_object_new_from_xtr_data (bin, bf, baseaddr, loadaddr, xtr_data))
				eprintf ("Error: failed to load the Extracted Objects with %s for %s.", xtr->name, bf->file);
		}
		r_bin_xtrdata_free (xtr_data);
	}

	if (bf && bf->narch > 1) {
		RBinObject *obj = r_list_get_n (bf->objs, 0);
		r_bin_file_set_cur_binfile_obj (bf->rbin, bf, obj);
	}
	return bf;
}

static RBinPlugin * r_bin_get_binplugin_by_name (RBin *bin, const char *name) {
	RBinPlugin *plugin;
	RListIter *it;
	if (!bin || !name) return NULL;
	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, name))
			return plugin;
		// must be set to null
		plugin = NULL;
	}
	return NULL;
}

R_API RBinPlugin * r_bin_get_binplugin_by_bytes (RBin *bin, const ut8* bytes, ut64 sz) {
	RBinPlugin *plugin;
	RListIter *it;
	if (!bin || !bytes)
		return NULL;
	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->check_bytes && plugin->check_bytes (bytes, sz) )
			return plugin;
		// must be set to null
		plugin = NULL;
	}
	return NULL;
}

static RBinXtrPlugin * r_bin_get_xtrplugin_by_name (RBin *bin, const char *name) {
	RBinXtrPlugin *xtr;
	RListIter *it;
	if (!bin || !name) return NULL;
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, name))
			return xtr;
		// must be set to null
		xtr = NULL;
	}
	return NULL;
}

static RBinPlugin * r_bin_get_binplugin_any (RBin *bin) {
	static RBinPlugin *any = NULL;
	if (!bin) return NULL;
	if (!any) any = r_bin_get_binplugin_by_name (bin, "any");
	return any;
}

static int r_bin_object_set_sections (RBinFile *bf, RBinObject *obj) {
	RIOBind *iob;
	RIO *io;
	if (!bf || !bf->rbin || !obj || !obj->info)
		return R_FALSE;
	iob = &(bf->rbin->iob);
	io = iob ? iob->get_io (iob) : NULL;
	if (!io || !iob)
		return R_FALSE;
#if 0
	// clear loaded sections
	//r_io_section_clear (io);
	r_list_free (io->sections);
	io->sections = r_list_new ();

	r_list_foreach (obj->sections, s_iter, s) {
		iob->section_add (io, s->paddr, s->vaddr, s->size, s->vsize, s->srwx, s->name, obj->id, bf->fd);
		iob->section_set_arch_bin_id (io, s->paddr, info->arch, info->bits, bf->id);
	}
#endif
	return R_TRUE;
}

static RBinObject * r_bin_object_new (RBinFile *binfile, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz) {
	const ut8 *bytes = binfile ? r_buf_buffer (binfile->buf) : NULL;
	ut64 bytes_sz = binfile ? r_buf_size (binfile->buf): 0;
	Sdb *sdb = binfile ? binfile->sdb : NULL;
	RBinObject *o = R_NEW0 (RBinObject);
	o->obj_size = bytes && (bytes_sz >= sz+offset) ? sz : 0;
	o->boffset = offset;
	o->id = r_num_rand (0xfffff000);
	o->kv = sdb_new0 ();

	o->baddr = baseaddr;
	// XXX more checking will be needed here
	if (bytes && plugin && plugin->load_bytes && (bytes_sz >= sz + offset) ) {
		o->bin_obj = plugin->load_bytes (bytes+offset, sz, loadaddr, sdb);
		if (!o->bin_obj) {
			eprintf("Error in r_bin_object_new: load_bytes failed for %s plugin\n",
				plugin->name);
			free (o);
			return NULL;
		}
	} else if (binfile && plugin && plugin->load) {
		// XXX - haha, this is a hack.
		// switching out the current object for the new
		// one to be processed
		RBinObject *old_o = binfile->o;
		binfile->o = o;
		if (plugin->load (binfile)) {
			binfile->sdb_info = o->kv;
// mark as do not walk
			sdb_ns_set (binfile->sdb, "info", o->kv);
		} else binfile->o = old_o;
		o->obj_size = sz;
	} else {
		free (o);
		return NULL;
	}

	o->plugin = plugin;
	o->loadaddr = loadaddr;
	o->baddr = baseaddr;
	// XXX - binfile could be null here meaning an improper load
	// XXX - object size cant be set here and needs to be set where 
	// where the object is created from.  The reason for this is to prevent
	// mis-reporting when the file is loaded from impartial bytes or is extracted
	// from a set of bytes in the file
	r_bin_object_set_items (binfile, o);
	r_bin_file_object_add (binfile, o);
	// XXX this is a very hacky alternative to rewriting the
	// RIO stuff, as discussed here:
	if (o->sections)
		r_bin_object_set_sections (binfile, o);
	return o;
}

static int r_bin_file_set_bytes (RBinFile *binfile, const ut8 * bytes, ut64 sz) {
	if (!bytes) return R_FALSE;
	if (binfile->buf) r_buf_free (binfile->buf);
	binfile->buf = r_buf_new ();
	r_buf_set_bytes (binfile->buf, bytes, sz);
	binfile->size = sz;
	return R_TRUE;
}

static RBinFile * r_bin_file_new (RBin *bin, const char *file, const ut8 * bytes, ut64 sz, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb) {
	RBinFile *binfile = R_NEW0 (RBinFile);

	r_bin_file_set_bytes (binfile, bytes, sz);

	binfile->rbin = bin;
	binfile->file = strdup (file);
	binfile->rawstr = rawstr;
	binfile->fd = fd;
	binfile->id = r_num_rand (0xfffff000);
	binfile->curxtr = r_bin_get_xtrplugin_by_name (bin, xtrname);
	binfile->sdb = sdb;
	binfile->size = file_sz;

	binfile->objs = r_list_newf ((RListFree)r_bin_object_free);

	if (!binfile->buf) {
		//r_bin_file_free (binfile);
		binfile->buf = r_buf_new ();
	//	return NULL;
	}

	if (sdb) {
		char fdkey[128];
		snprintf (fdkey, sizeof (fdkey)-1, "fd.%i", fd);
		binfile->sdb = sdb_ns (sdb, fdkey, 1);
		sdb_set (binfile->sdb, "archs", "0:0:x86:32", 0); // x86??
		/* NOTE */
		/* Those refs++ are necessary because sdb_ns() doesnt rerefs all sub-namespaces */
		/* And if any namespace is referenced backwards it gets double-freed */
		binfile->sdb_addrinfo = sdb_ns (binfile->sdb, "addrinfo", 1);
		binfile->sdb_addrinfo->refs++;
		sdb_ns_set (sdb, "cur", binfile->sdb);
		binfile->sdb->refs++;
	}
	return binfile;
}

static int r_bin_file_object_new_from_xtr_data (RBin *bin, RBinFile *bf, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data) {
	RBinObject *o = NULL;
	RBinPlugin *plugin = NULL;
	ut64 offset = data ? data->offset : 0;

	// for right now the bytes used will just be the offest into the binfile buffer
	// if the extraction requires some sort of transformation then this will need to be fixed
	// here.
	const ut8 * bytes = data ? r_buf_buffer (data->buf) : NULL;
	ut64 sz = data ? r_buf_size (data->buf) : 0;
	//if (!data || !data->buf) return bf;
	if (!data || !bf) return R_FALSE;

	plugin = r_bin_get_binplugin_by_bytes (bin, bytes, sz);
	if (!plugin) plugin = r_bin_get_binplugin_any (bin);
	o = r_bin_object_new (bf, plugin, baseaddr, loadaddr, offset, sz);
	// size is set here because the reported size of the object depends on if loaded from xtr plugin or partially read
	if (o && !o->size) o->size = sz;

	if (!o) return R_FALSE;
	bf->narch = data->file_count;
	return R_TRUE;
}

static RBinFile * r_bin_file_new_from_bytes (RBin *bin, const char *file, const ut8 * bytes, ut64 sz, ut64 file_sz, int rawstr, ut64 baseaddr,
		 ut64 loadaddr, int fd, const char *pluginname, const char *xtrname, ut64 offset) {
	RBinPlugin *plugin = NULL;
	RBinXtrPlugin *xtr = NULL;
	RBinFile *bf = NULL;
	RBinObject *o = NULL;
	ut8 binfile_created = R_FALSE;

	if (xtrname) xtr = r_bin_get_xtrplugin_by_name (bin, xtrname);

	if (xtr && xtr->check && xtr->check_bytes (bytes, sz)) {
		return r_bin_file_xtr_load_bytes (bin, xtr, file,
			bytes, sz, file_sz, baseaddr, loadaddr, 0,
			fd, rawstr);
	}

	if (!bf) {
		bf = r_bin_file_create_append (bin, file, bytes, sz, file_sz, rawstr, fd, xtrname);
		if (!bf) return NULL;
		binfile_created = R_TRUE;
	}

	if (pluginname) plugin = r_bin_get_binplugin_by_name (bin, pluginname);
	if (!plugin) plugin = r_bin_get_binplugin_by_bytes (bin, bytes, sz);
	if (!plugin) plugin = r_bin_get_binplugin_any (bin);

	o = r_bin_object_new (bf, plugin, baseaddr, loadaddr, 0, r_buf_size (bf->buf));
	// size is set here because the reported size of the object depends on if loaded from xtr plugin or partially read
	if (o && !o->size) o->size = file_sz;

	if (!o) {
		if (bf && binfile_created) r_list_delete_data (bin->binfiles, bf);
		return NULL;
	}
	if (strcmp (plugin->name, "any") )
		bf->narch = 1;

	return bf;
}

R_API int r_bin_add(RBin *bin, RBinPlugin *foo) {
	RListIter *it;
	RBinPlugin *plugin;
	if (foo->init)
		foo->init (bin->user);
	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, foo->name))
			return R_FALSE;
	}
	plugin = R_NEW0 (RBinPlugin);
	memcpy (plugin, foo, sizeof (RBinPlugin));
	r_list_append (bin->plugins, plugin);
	return R_TRUE;
}

R_API int r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo) {
	RListIter *it;
	RBinXtrPlugin *xtr;

	if (foo->init)
		foo->init (bin->user);

	// avoid duplicates
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, foo->name))
			return R_FALSE;
	}
	r_list_append (bin->binxtrs, foo);

	return R_TRUE;
}

R_API void* r_bin_free(RBin *bin) {
	if (!bin) return NULL;

	bin->file = NULL;
	//r_bin_free_bin_files (bin);
	r_list_free (bin->binfiles);
	r_list_free (bin->binxtrs);
	r_list_free (bin->plugins);
	sdb_free (bin->sdb);
	memset (bin, 0, sizeof (RBin));
	free (bin);
	return NULL;
}

R_API int r_bin_list(RBin *bin) {
	RListIter *it;
	RBinXtrPlugin *bp;
	RBinXtrPlugin *bx;
	r_list_foreach (bin->plugins, it, bp) {
		printf ("bin  %-11s %s (%s)\n",
			bp->name, bp->desc, bp->license);
	}
	r_list_foreach (bin->binxtrs, it, bx) {
		printf ("xtr  %-11s %s (%s)\n", bx->name,
			bx->desc, bx->license);
	}
	return R_FALSE;
}

R_API ut64 r_bin_get_baddr(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) return o->baddr;
	return 0LL;
}

R_API void r_bin_set_baddr(RBin *bin, ut64 baddr) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) {
		o->baddr = baddr;
		// XXX - update all the infos?
	}
}

R_API ut64 r_bin_get_boffset(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->boffset;
	return UT64_MAX;
}

R_API RBinAddr* r_bin_get_sym(RBin *bin, int sym) {
	RBinObject *o = r_bin_cur_object (bin);
	if (sym<0 || sym>=R_BIN_SYM_LAST)
		return NULL;
	if (o)
		return o->binsym[sym];
	return NULL;
}

// XXX: those accessors are redundant
R_API RList* r_bin_get_entries(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->entries;
	return NULL;
}

R_API RList* r_bin_get_fields(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->fields;
	return NULL;
}

R_API RList* r_bin_get_imports(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) return o->imports;
	return NULL;
}

R_API RBinInfo* r_bin_get_info(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (!o) return NULL;
	return o->info;
}

R_API RList* r_bin_get_libs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) return o->libs;
	return NULL;
}

R_API RList* r_bin_get_relocs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) return o->relocs;
	return NULL;
}

R_API RList* r_bin_get_sections(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) return o->sections;
	return NULL;
}

// TODO: MOve into section.c and rename it to r_io_section_get_at ()
R_API RBinSection* r_bin_get_section_at(RBinObject *o, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;

	if (o) {
		// TODO: must be O(1) .. use sdb here
		r_list_foreach (o->sections, iter, section) {
			from = va ? o->baddr+section->vaddr: section->paddr;
			to = va ? (o->baddr+section->vaddr + section->vsize) :
					  (section->paddr+ section->size);
			if (off >= from && off < to)
				return section;
		}
	}
	return NULL;
}

R_API RList* r_bin_reset_strings(RBin *bin) {
	RBinFile *a = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);

	if (!a || !o) return NULL;
	if (o->strings) {
		r_list_purge (o->strings);
		o->strings = NULL;
	}

	if (bin->minstrlen <= 0)
		return NULL;
	a->rawstr = bin->rawstr;

	if (plugin && plugin->strings)
		o->strings = plugin->strings (a);
	else o->strings = get_strings (a, bin->minstrlen, 0);
	return o->strings;
}

R_API RList* r_bin_get_strings(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->strings: NULL;
}

R_API RList* r_bin_get_symbols(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->symbols: NULL;
}

R_API int r_bin_is_big_endian (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->info->big_endian: R_FALSE;
}

R_API int r_bin_is_stripped (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_STRIPPED & o->info->dbg_info): 1;
}

R_API int r_bin_is_static (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o && r_list_length (o->libs)>0)
		return R_BIN_DBG_STATIC & o->info->dbg_info;
	return R_TRUE;
}

// TODO: Integrate with r_bin_dbg */
R_API int r_bin_has_dbg_linenums (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_LINENUMS & o->info->dbg_info): R_FALSE;
}

R_API int r_bin_has_dbg_syms (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_SYMS & o->info->dbg_info): R_FALSE;
}

R_API int r_bin_has_dbg_relocs (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o?(R_BIN_DBG_RELOCS & o->info->dbg_info): R_FALSE;
}

R_API RBin* r_bin_new() {
	int i;
	RBinXtrPlugin *static_xtr_plugin;
	RBin *bin = R_NEW0 (RBin);
	if (!bin) return NULL;
	bin->sdb = sdb_new0 ();
	bin->printf = (PrintfCallback)printf;
	bin->plugins = r_list_new();
	bin->plugins->free = free;
	bin->minstrlen = 0;
	bin->cur = NULL;

	bin->binfiles = r_list_newf ((RListFree)r_bin_file_free);
	for (i=0; bin_static_plugins[i]; i++) {
		r_bin_add (bin, bin_static_plugins[i]);
	}
	bin->binxtrs = r_list_new ();
	bin->binxtrs->free = free;
	for (i=0; bin_xtr_static_plugins[i]; i++) {
		static_xtr_plugin = R_NEW0 (RBinXtrPlugin);
		*static_xtr_plugin = *bin_xtr_static_plugins[i];
		r_bin_xtr_add (bin, static_xtr_plugin);
	}
	return bin;
}

R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits, name);
	RBinObject *obj = NULL;
	if (binfile) {
		obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	} else {
		void *plugin = r_bin_get_binplugin_by_name (bin, name);
		if (plugin) {
			if (bin->cur)
				bin->cur->curplugin = plugin;
			binfile = r_bin_file_new (bin, "-", NULL, 0, 0, 0, 999, NULL, NULL);
			// create object and set arch/bits
			obj = r_bin_object_new (binfile, plugin, 0, 0, 0, 1024);
			binfile->o = obj;
			obj->info = R_NEW0 (RBinInfo);
			strcpy (obj->info->arch, arch);
			obj->info->bits = bits;
		}
	}
	return (binfile && r_bin_file_set_cur_binfile_obj (bin, binfile, obj));
}

R_API RBinObject * r_bin_object_find_by_arch_bits (RBinFile *binfile, const char *arch, int bits, const char *name) {
	RBinObject *obj = NULL;
	RListIter *iter = NULL;
	RBinInfo *info = NULL;
	r_list_foreach (binfile->objs, iter, obj) {
		info = obj->info;
		if (info && (bits == info->bits) &&
			!strcmp (info->arch, arch) &&
			!strcmp (info->file, name)){
			break;
		}
		obj = NULL;
	}
	return obj;
}

R_API RBinFile * r_bin_file_find_by_arch_bits(RBin *bin, const char *arch, int bits, const char *name) {
	RListIter *iter ;
	RBinFile *binfile = NULL;
	RBinObject *o = NULL;

	if (!name || !arch) return NULL;
	r_list_foreach (bin->binfiles, iter, binfile) {
		o = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
		if (o) break;
		binfile = NULL;
	}
	return binfile;
}


R_API int r_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	RBinFile *cur =  r_bin_cur (bin),
			*binfile = NULL;
	RBinObject *obj = NULL;
	name = !name && cur ? cur->file : name;
	binfile = r_bin_file_find_by_arch_bits (bin, arch, bits, name);
	if (binfile && name) {
		obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	}
	return binfile && r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API int r_bin_select_object(RBinFile *binfile, const char *arch, int bits, const char *name) {
	RBinObject *obj = binfile ? r_bin_object_find_by_arch_bits (binfile, arch, bits, name) : NULL;
	return obj && r_bin_file_set_cur_binfile_obj (binfile->rbin, binfile, obj);
}

static RBinObject* r_bin_file_object_find_by_id (RBinFile *binfile, ut32 binobj_id) {
	RBinObject *obj;
	RListIter *iter;

	if (binfile)
	r_list_foreach (binfile->objs, iter, obj) {
		if (obj->id == binobj_id)
			return obj;
	}
	return NULL;
}

static RBinFile* r_bin_file_find_by_object_id (RBin *bin, ut32 binobj_id) {
	RListIter *iter;
	RBinFile *binfile;
	r_list_foreach (bin->binfiles, iter, binfile) {
		if (r_bin_file_object_find_by_id (binfile, binobj_id))
			return binfile;
	}
	return NULL;
}

#if 0
static RBinObject * r_bin_object_find_by_id (RBin *bin, ut32 binobj_id) {
	RBinFile *binfile = NULL;
	RBinObject *obj = NULL;
	RListIter *iter = NULL;

	r_list_foreach (bin->binfiles, iter, binfile) {
		obj = r_bin_file_object_find_by_id (binfile, binobj_id);
		if (obj) break;
	}
	return obj;
}
#endif

static RBinFile * r_bin_file_find_by_id (RBin *bin, ut32 binfile_id) {
	RBinFile *binfile = NULL;
	RListIter *iter = NULL;

	r_list_foreach (bin->binfiles, iter, binfile) {
		if (binfile->id == binfile_id) break;
		binfile = NULL;
	}
	return binfile;
}

R_API int r_bin_object_delete (RBin *bin, ut32 binfile_id, ut32 binobj_id) {
	RBinFile *binfile = NULL;//, *cbinfile = r_bin_cur (bin);
	RBinObject *obj = NULL;
	int res = R_FALSE;

	if (binfile_id == UT32_MAX && binobj_id == UT32_MAX)
		return R_FALSE;

	if (binfile_id == -1) {
		binfile = r_bin_file_find_by_object_id (bin, binobj_id);
		obj = binfile ? r_bin_file_object_find_by_id (binfile, binobj_id) : NULL;
	} else if (binobj_id == -1) {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile ? binfile->o : NULL;
	} else {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile ? r_bin_file_object_find_by_id (binfile, binobj_id) : NULL;
	}

	// lazy way out, always leaving at least 1 bin object loaded
	if (binfile && (r_list_length (binfile->objs) > 1)) {
		binfile->o = NULL;
		r_list_delete_data (binfile->objs, obj);
		obj = (RBinObject *) r_list_get_n (binfile->objs, 0);
		res = obj && binfile && r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
	}
	return res;
}

R_API int r_bin_select_by_ids(RBin *bin, ut32 binfile_id, ut32 binobj_id ) {
	RBinFile *binfile = NULL;
	RBinObject *obj = NULL;

	if (binfile_id == UT32_MAX && binobj_id == UT32_MAX) {
		return R_FALSE;
	}

	if (binfile_id == -1 ) {
		binfile = r_bin_file_find_by_object_id (bin, binobj_id);
		obj = binfile ? r_bin_file_object_find_by_id (binfile, binobj_id) : NULL;
	} else if (binobj_id == -1) {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile ? binfile->o : NULL;
	} else {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile ? r_bin_file_object_find_by_id (binfile, binobj_id) : NULL;
	}

	if (!binfile || !obj) return R_FALSE;

	return obj && binfile && r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API int r_bin_select_idx(RBin *bin, const char *name, int idx) {
	RBinFile *nbinfile = NULL, *binfile = r_bin_cur (bin);
	RBinObject *obj = NULL;
	const char *tname = !name && binfile ? binfile->file : name;
	int res = R_FALSE;
	if (!tname || !bin) return res;
	nbinfile = r_bin_file_find_by_name_n (bin, tname, idx);
	obj = nbinfile ? r_list_get_n (nbinfile->objs, idx) : NULL;
	return obj && nbinfile && r_bin_file_set_cur_binfile_obj (bin, nbinfile, obj);
}

R_API void r_bin_list_archs(RBin *bin, int mode) {
	RListIter *iter;
	int i = 0;
	char archline[128];
	char unknown_[128];
	RBinFile *binfile = r_bin_cur (bin);
	RBinObject *obj = NULL;
	const char *name = binfile ? binfile->file : NULL;
	int narch = binfile ? binfile->narch : 0;


	Sdb *binfile_sdb = binfile ? binfile->sdb : NULL;
	if (!binfile_sdb) {
		eprintf ("Cannot find SDB!\n");
		return;
	} else if (!binfile) {
		eprintf ("Binary format not currently loaded!\n");
		return;
	}
	sdb_unset (binfile_sdb, ARCHS_KEY, 0);

	RBinFile *nbinfile = r_bin_file_find_by_name_n (bin, name, i);
	if (!nbinfile) return;
	i = -1;
	r_list_foreach (nbinfile->objs, iter, obj){

		RBinInfo *info = obj->info;
		char bits = info ? info->bits : 0;
		ut64 boffset = obj->boffset;
		ut32 obj_size = obj->obj_size;
		const char *arch = info ? info->arch : NULL;
		const char *machine = info ? info->machine : "unknown_machine";

		++i;
		if (!arch) {
			snprintf (unknown_, sizeof (unknown_), "unk_%d", i);
			arch = unknown_;
		}

		if (info && narch > 1) {
			if (mode)
				printf ("%03i 0x%08"PFMT64x" %d %s_%i %s\n", i,
					boffset, obj_size, arch, bits, machine);

			snprintf (archline, sizeof (archline)-1,
				"0x%08"PFMT64x":%d:%s:%d:%s",
				 boffset, obj_size, arch, bits, machine);
			/// xxx machine not exported?
			//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
		} else {
			if (info) {
				if (mode)
					printf ("%03i 0x%08"PFMT64x" %d %s_%d\n", i,
						boffset, obj_size, arch, bits);

				snprintf (archline, sizeof (archline),
					"0x%08"PFMT64x":%d:%s:%d",
					 boffset, obj_size, arch, bits);
			} else if (nbinfile && mode) {
				if (mode)
					printf ("%03i 0x%08"PFMT64x" %d unk_0\n", i,
					 boffset, obj_size);

				snprintf (archline, sizeof (archline),
					"0x%08"PFMT64x":%d:%s:%d",
					 boffset, obj_size, "unk", 0);
			} else {
				eprintf ("Error: Invalid RBinFile.\n");
			}
			//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
		}
	}
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static int getoffset (RBin *bin, int type, int idx) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (plugin && plugin->get_offset)
		return plugin->get_offset (a, type, idx);
	return -1;
}

static const char *getname (RBin *bin, int off) {
	// walk symbols, find index, return name, ignore offset wtf
	return NULL;
}

R_API void r_bin_bind (RBin *bin, RBinBind *b) {
	if (b) {
		b->bin = bin;
		b->get_offset = getoffset;
		b->get_name = getname;
	}
}

R_API RBuffer *r_bin_create (RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (codelen<0) codelen = 0;
	if (datalen<0) datalen = 0;
	if (plugin && plugin->create)
		return plugin->create (bin, code, codelen, data, datalen);
	return NULL;
}

R_API RBinObject *r_bin_get_object(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) o->referenced++;
	return o;
}


R_API RList* /*<RBinClass>*/r_bin_get_classes(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->classes;
	return NULL;
}

R_API RBinClass *r_bin_class_new (RBinFile *binfile, const char *name, const char *super, int view) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RList *list = NULL;
	RBinClass *c;
	if (!o)
		return NULL;

	list = o->classes;
	if (!name) return NULL;
	c = r_bin_class_get (binfile, name);
	if (c) {
		if (super) {
			free (c->super);
			c->super = strdup (super);
		}
		return c;
	}
	c = R_NEW0 (RBinClass);
	if (!c) return NULL;
	c->name = strdup (name);
	c->super = super? strdup (super): NULL;
	c->index = r_list_length (list);
	c->methods = r_list_new ();
	c->fields = r_list_new ();
	c->visibility = view;
	if (!list)
		list = o->classes = r_list_new ();
	r_list_append (list, c);
	return c;
}

R_API RBinClass *r_bin_class_get (RBinFile *binfile, const char *name) {
	RBinObject *o = binfile ? binfile->o : NULL;
	RList *list = NULL;
	RListIter *iter;
	RBinClass *c;

	if (!o) return NULL;
	list = o->classes;
	r_list_foreach (list, iter, c) {
		if (!strcmp (c->name, name))
			return c;
	}
	return NULL;
}

R_API int r_bin_class_add_method (RBinFile *binfile, const char *classname, const char *name, int nargs) {
	RBinClass *c = r_bin_class_get (binfile, classname);
	char *n = strdup (name);
	if (c) {
		r_list_append (c->methods, (void*)n);
		return R_TRUE;
	}
	c = r_bin_class_new (binfile, classname, NULL, 0);
	r_list_append (c->methods, (void*)n);
	return R_FALSE;
}

R_API void r_bin_class_add_field (RBinFile *binfile, const char *classname, const char *name) {
//TODO: add_field into class
	//eprintf ("TODO add field: %s \n", name);
}

R_API ut64 r_bin_get_offset (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	if (binfile) return binfile->offset;
	return UT64_MAX;
}

R_API ut64 r_binfile_get_vaddr (RBinFile *binfile, ut64 baddr, ut64 paddr, ut64 vaddr) {
	int use_va = 0;
	if (binfile && binfile->o && binfile->o->info)
		use_va = binfile->o->info->has_va;
	return use_va? vaddr: paddr;
}

R_API ut64 r_bin_get_vaddr (RBin *bin, ut64 baddr, ut64 paddr, ut64 vaddr) {
	if (!bin || !bin->cur)
		return UT64_MAX;
	// autodetect thumb
	if (bin->cur->o && bin->cur->o->info) {
		if (!strcmp (bin->cur->o->info->arch, "arm")) {
			if (vaddr & 1) {
				vaddr = (vaddr>>1)<<1;
			}
		}
	}
	return r_binfile_get_vaddr (bin->cur, baddr, paddr, vaddr);
}

R_API ut64 r_bin_get_size (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) return o->size;
	return UT64_MAX;
}

R_API int r_bin_file_delete(RBin *bin, ut32 bin_fd) {
	RListIter *iter;
	RBinFile *bf;

	if (bin)
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->fd == bin_fd) {
			r_list_delete (bin->binfiles, iter);
			return 1;
		}
	}
	return 0;
}

R_API RBinFile * r_bin_file_find_by_fd (RBin *bin, ut32 bin_fd) {
	RListIter *iter;
	RBinFile *bf;
	if (bin)
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->fd == bin_fd)
			return bf;
	}
	return NULL;
}

R_API RBinFile * r_bin_file_find_by_name (RBin * bin, const char * name) {
	RListIter *iter;
	RBinFile *bf = NULL;

	if (!bin) return bf;
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->file && !strcmp (bf->file, name)) break;
		bf = NULL;
	}
	return bf;
}

R_API RBinFile * r_bin_file_find_by_name_n (RBin * bin, const char * name, int idx) {
	RListIter *iter;
	RBinFile *bf = NULL;
	int i = 0;
	if (!bin) return bf;

	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->file && !strcmp (bf->file, name)) {
			if (i == idx) break;
			i++;
		}
		bf = NULL;
	}
	return bf;
}

R_API int r_bin_file_set_cur_by_fd (RBin * bin, ut32 bin_fd) {
	RBinFile *bf = r_bin_file_find_by_fd (bin, bin_fd);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API int r_bin_file_set_cur_binfile_obj (RBin * bin, RBinFile *bf, RBinObject *obj) {
	RBinPlugin *plugin = NULL;
	if (!bin || !bf || !obj) return R_FALSE;
	bin->file = bf->file;
	bin->cur = bf;
	bin->narch = bf->narch;
	bf->o = obj;
	plugin = r_bin_file_cur_plugin (bf);
	if (bin->minstrlen <1)
		bin->minstrlen = plugin ? plugin->minstrlen : bin->minstrlen;
	r_bin_object_set_sections (bf, obj);
	return R_TRUE;

}

R_API int r_bin_file_set_cur_binfile (RBin * bin, RBinFile *bf) {
	RBinObject *obj = bf ? bf->o : NULL;
	if (!obj) return R_FALSE;
	return r_bin_file_set_cur_binfile_obj (bin, bf, obj);
}

R_API int r_bin_file_set_cur_by_name (RBin * bin, const char * name) {
	RBinFile *bf = r_bin_file_find_by_name (bin, name);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API RBinFile * r_bin_cur (RBin *bin) {
	return bin? bin->cur: NULL;
}

R_API RBinObject * r_bin_cur_object (RBin *bin) {
	RBinFile *binfile = r_bin_cur (bin);
	return binfile? binfile->o: NULL;
}
