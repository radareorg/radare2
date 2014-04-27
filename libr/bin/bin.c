/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

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

static void get_strings_range(RBinFile *arch, RList *list, int min, ut64 from, ut64 to, ut64 scnrva);
static int is_data_section(RBinFile *a, RBinSection *s);
static RList* get_strings(RBinFile *a, int min);
static void r_bin_object_delete_items (RBinObject *o);
static void r_bin_object_free (void /*RBinObject*/ *o_);
static void set_bin_items(RBinFile *binfile, RBinPlugin *cp);
static int remove_bin_file_by_binfile (RBin *bin, RBinFile * binfile);
//static void r_bin_free_bin_files (RBin *bin);
static void r_bin_file_free (void /*RBinFile*/ *bf_);
static int r_bin_file_new_from_xtr_data (RBin* bin, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data, int fd, int rawstr);
static int r_bin_files_populate_from_xtrlist (RBin *bin, ut64 baseaddr, ut64 loadaddr, RList *xtr_data_list, int fd, int rawstr);
static int r_bin_file_xtr_load_bytes (RBin *bin, RBinXtrPlugin *xtr, const ut8 *bytes, ut64 sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
static int r_bin_file_xtr_load (RBin *bin, RBinXtrPlugin *xtr, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
static RBinFile * r_bin_file_new (RBin *bin, const char *file, const ut8 * bytes, ut64 sz, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd);
static int r_bin_file_load(RBin *bin, int rawstr, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd);
static int r_bin_file_local_load (RBin *bin, RBuffer *buf, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd);
static int getoffset (RBin *bin, int type, int idx);
static const char *getname (RBin *bin, int off);

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


static void get_strings_range(RBinFile *arch, RList *list, int min, ut64 from, ut64 to, ut64 scnrva) {
	char str[R_BIN_SIZEOF_STRINGS];
	int i, matches = 0, ctr = 0;
	RBinString *ptr = NULL;
	char type = 'A';

	if (!arch->rawstr)
		if (!arch->curplugin || !arch->curplugin->info)
			return;
	if (arch->curplugin && min==0)
		min = arch->curplugin->minstrlen;
	if (min==0)
		min = 4; // defaults
	if (min <= 0)
		return;

	if (arch && arch->buf && (!to || to > arch->buf->length))
		to = arch->buf->length;
	if (to != 0 && (to<1 || to > 0xf00000)) {
		eprintf ("WARNING: bin_strings buffer is too big at 0x%08"PFMT64x"\n", from);
		return;
	}
	if (!arch->buf)
		return;
	if (to == 0 && arch->buf)
		to = arch->buf->length;
	if (arch->buf && arch->buf->buf)
	for (i = from; i < to; i++) {
		if ((IS_PRINTABLE (arch->buf->buf[i])) && \
				matches < R_BIN_SIZEOF_STRINGS-1) {
			str[matches] = arch->buf->buf[i];
			/* add support for wide char strings */
			if (arch->buf->buf[i+1]==0) {
				if (IS_PRINTABLE (arch->buf->buf[i+2])) {
					if (arch->buf->buf[i+3]==0) {
						i++;
						type = 'W';
					}
				}
			}
			matches++;
			continue;
		}
		/* check if the length fits in our request */
		if (matches >= min) {
			if (!(ptr = R_NEW (RBinString))) {
				eprintf ("Error allocating string\n");
				break;
			}
			str[matches] = '\0';
			ptr->offset = i-matches;
			if (scnrva) {
				ptr->rva = (ptr->offset+scnrva-from);
			} else {
				ptr->rva = ptr->offset;
			}
			//HACK if (scnrva) ptr->rva = ptr->offset-from+scnrva; else ptr->rva = ptr->offset;
			ptr->size = matches+1;
			ptr->length = ptr->size << ((type=='W')? 1:0);
			ptr->type = type;
			type = 'A';
			ptr->ordinal = ctr;
			// copying so many bytes here..
			memcpy (ptr->string, str, R_BIN_SIZEOF_STRINGS);
			ptr->string[R_BIN_SIZEOF_STRINGS-1] = '\0';
			//r_name_filter (ptr->string, R_BIN_SIZEOF_STRINGS-1);
			r_list_append (list, ptr);
			//if (!sdb_add (DB, 
			ctr++;
		}
		matches = 0;
	}
}

static int is_data_section(RBinFile *a, RBinSection *s) {
	RBinObject *o = a->o;
	if (strstr (o->info->bclass, "MACH0") && strstr (s->name, "_cstring")) // OSX
		return 1;
	if (strstr (o->info->bclass, "ELF") && strstr (s->name, "data") && !strstr (s->name, "rel")) // LINUX
		return 1;
#define X 1
#define ROW (4|2)
	if (strstr (o->info->bclass, "PE") && s->srwx & ROW && !(s->srwx&X) && s->size>0 )
		return 1;
	if (strstr (s->name, "_const")) // Rust
		return 1;
	return 0;
}

static RList* get_strings(RBinFile *a, int min) {
	int count = 0;
	RListIter *iter;
	RBinSection *section;
	RBinObject *o = a? a->o : NULL;

	RList *ret = r_list_new ();
	if (!ret) {
		eprintf ("Error allocating array\n");
		return NULL;
	} else if (!o) {
		eprintf ("Error bin object unitialized\n");
		return ret;
	}
	ret->free = free;

	if (o->sections && !a->rawstr) {
		r_list_foreach (o->sections, iter, section) {
			if (is_data_section (a, section)) {
				count++;
				get_strings_range (a, ret, min,
					section->offset,
					section->offset+section->size,
					section->rva);
			}
		}
		if (r_list_empty (o->sections)) {
			int i, next = 0, from = 0, funn = 0, to = 0;
			ut8 *buf = a->buf->buf;
			for (i=0; i<a->buf->length; i++) {
				if (!buf[i] || IS_PRINTABLE (buf[i])) {
					if (buf[i]) {
						if (!from) from = i;
						funn++;
						next = 0;
					}
				} else {
					next++;
					if (next>5) from = 0;
					if (!to) to = i;
					to = i;
					if (from && next==5 && funn>16) {
						get_strings_range (a, ret, min, from, to, 0);
				//eprintf ("FUNN %d\n", funn);
				//eprintf ("MIN %d %d\n", from, to);
						funn = 0;
						from = 0;
						to = 0;
					}
				}
			}
		}
	} else {
		get_strings_range (a, ret, min,
			0, a->size, 0);
	}
	return ret;
}

R_API int r_bin_load_languages(RBinFile *binfile) {
	if (r_bin_lang_objc (binfile))
		return R_BIN_NM_OBJC;
	if (r_bin_lang_cxx (binfile))
		return R_BIN_NM_CXX;
	return R_BIN_NM_NONE;
}

R_API void r_bin_update_items(RBin *bin, RBinPlugin *cp) {
	RBinFile *binfile = bin->cur;
	if (binfile) {
		r_bin_object_delete_items (binfile->o);
		set_bin_items (binfile, cp);
	}
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

	o->baddr = 0;
	o->boffset = 0;
	o->size = 0;


	memset (o, 0, sizeof (RBinObject));
	free (o);
}
// XXX - change this to RBinFile instead of RBin
static void set_bin_items(RBinFile *binfile, RBinPlugin *cp) {
	RBinObject *o = binfile ? binfile->o : NULL;
	int i, minlen = cp->minstrlen;

	if (!binfile || !o) return;
	if (cp->baddr) o->baddr = cp->baddr (binfile);
	if (cp->boffset) o->boffset = cp->boffset (binfile);
	// XXX: no way to get info from xtr pluginz?
	if (cp->size) o->size = cp->size (binfile);
	if (cp->binsym)
		for (i=0; i<R_BIN_SYM_LAST; i++)
			o->binsym[i] = cp->binsym (binfile, i);
	if (cp->entries) o->entries = cp->entries (binfile);
	if (cp->fields) o->fields = cp->fields (binfile);
	if (cp->imports) o->imports = cp->imports (binfile);
	o->info = cp->info? cp->info (binfile): NULL;
	if (cp->libs) o->libs = cp->libs (binfile);
	if (cp->relocs) o->relocs = cp->relocs (binfile);
	if (cp->sections) o->sections = cp->sections (binfile);
	if (cp->strings) o->strings = cp->strings (binfile);
	else o->strings = get_strings (binfile, minlen);
	if (cp->symbols) o->symbols = cp->symbols (binfile);
	if (cp->classes) o->classes = cp->classes (binfile);
	if (cp->lines) o->lines = cp->lines (binfile);
	o->lang = r_bin_load_languages (binfile);
}

R_API int r_bin_io_load(RBin *bin, RIO *io, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int xtr_idx) {
	RListIter *it;
	ut8* buf_bytes;
	RBinXtrPlugin *xtr;
	ut64 start, end, sz = UT64_MAX;
	RBinFile *binfile = NULL;
	int rawstr = 0;

	if (!desc || !desc->plugin || !desc->plugin->read || !desc->plugin->lseek)
		return R_FALSE;

	buf_bytes = NULL;
	end = desc->plugin->lseek (io, desc, 0, SEEK_END);
	start = desc->plugin->lseek (io, desc, 0, SEEK_SET);

	if (end == UT64_MAX || start == UT64_MAX)
		return R_FALSE;

	sz = end - start;
	if (sz>(64*1024*1024)) // too big, probably wrong
		return R_FALSE;

	buf_bytes = malloc (sz);

	if (!buf_bytes || !desc->plugin->read (io, desc, buf_bytes, sz)) {
		free (buf_bytes);
		return R_FALSE;
	}

	r_list_foreach (bin->binxtrs, it, xtr) {
		if (xtr->check && xtr->check (bin)) {
			if (xtr && (xtr->extractall_from_bytes || xtr->extract_from_bytes))
				return r_bin_file_xtr_load_bytes (bin, xtr, buf_bytes, sz, baseaddr, loadaddr, xtr_idx, desc->fd, rawstr);
			xtr = NULL;
		}
	}

	binfile = r_bin_file_new (bin, desc->name, buf_bytes, sz, rawstr, baseaddr, loadaddr, desc->fd);
	return r_bin_file_set_cur_binfile (bin, binfile);
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

	if (!a) return;

	// Binary format objects are connected to the
	// RBinObject, so the plugin must destroy the
	// format data first
	if (a->curplugin && a->curplugin->destroy)
		a->curplugin->destroy (a);

	if (a->curxtr && a->curxtr->destroy)
		a->curxtr->destroy ((void *)a);

	if (a->o) r_bin_object_free (a->o);
	a->o = NULL;

	if (a->buf) r_buf_free (a->buf);
	// TODO: unset related sdb namespaces
	if (a && a->sdb_addrinfo) {
		sdb_free (a->sdb_addrinfo);
		a->sdb_addrinfo = NULL;
	}
	free (a->file);
	memset (a, 0, sizeof (RBinFile));
}

static int r_bin_file_new_from_xtr_data (RBin* bin, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data, int fd, int rawstr) {
	int res = data && data->buf && r_bin_file_local_load (bin, data->buf, rawstr, baseaddr, loadaddr, fd);
	if (res) {
		RBinFile *bf = r_bin_cur (bin);
		RBinObject *o = r_bin_cur_object (bin);
		o->loadaddr = baseaddr + loadaddr;
		o->boffset = data->offset;
		o->size = data->size;
		bf->narch = data->file_count;
	}
	return res;
}

static int r_bin_files_populate_from_xtrlist (RBin *bin, ut64 baseaddr, ut64 loadaddr, RList *xtr_data_list, int fd, int rawstr) {
	RListIter *iter = NULL;
	RBinXtrData *data = NULL;
	int res = R_FALSE;
	r_list_foreach (xtr_data_list, iter, data) {
		res = r_bin_file_new_from_xtr_data  (bin, baseaddr, loadaddr, data, fd, rawstr);
		if (!res) break;
	}
	return res;
}

static int r_bin_file_xtr_load_bytes (RBin *bin, RBinXtrPlugin *xtr, const ut8 *bytes, ut64 sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr) {
	/*
		The Index array  for r_bin_file_xtr_load begins at 1, for convenience purposes.
	*/
	int res = R_FALSE;
	if (idx == 0 && xtr && xtr && bytes) {
		RList *xtr_data_list = xtr->extractall_from_bytes (bytes, sz);
		if (xtr_data_list){
			res = r_bin_files_populate_from_xtrlist (bin, baseaddr, loadaddr, xtr_data_list, fd, rawstr);
		}
		r_list_free (xtr_data_list);
	} else if (xtr && xtr->extract_from_bytes) {
		if (idx == 0) idx = 1;
		RBinXtrData *xtr_data = xtr->extract_from_bytes (bytes, sz, idx);
		if (xtr_data){
			res = r_bin_file_new_from_xtr_data (bin, baseaddr, loadaddr, xtr_data, fd, rawstr);
		}
		r_bin_xtrdata_free (xtr_data);
	}
	return res;
}

static int r_bin_file_xtr_load (RBin *bin, RBinXtrPlugin *xtr, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr) {
	/*
		The Index array  for r_bin_file_xtr_load begins at 1, for convenience purposes.
	*/
	ut32 sz = 0;
	char *bytes = bin->file ? r_file_slurp (bin->file, (int*)&sz) : NULL;
	return bytes && sz > 0 && r_bin_file_xtr_load_bytes (bin, xtr, (ut8*)bytes, sz, baseaddr, loadaddr, idx, fd, rawstr);
	/* Below is legacy. we should always try to load from bytes, because its what the body craves.

	int res = R_FALSE;
	if (idx == 0 && xtr && xtr) {
		RList *xtr_data_list = xtr->extractall (bin);
		if (xtr_data_list){
			res = r_bin_files_populate_from_xtrlist (bin, baseaddr, loadaddr, xtr_data_list, fd, rawstr);
		}
		r_list_free (xtr_data_list);
	} else if (xtr && xtr->extract) {
		if (idx == 0) idx = 1;
		RBinXtrData *xtr_data = xtr->extract (bin, idx);
		if (xtr_data){
			res = r_bin_file_new_from_xtr_data (bin, baseaddr, loadaddr, xtr_data, fd, rawstr);
		}
		r_bin_xtrdata_free (xtr_data);
	}
	return res;
	*/
}

static RBinFile * r_bin_file_new (RBin *bin, const char *file, const ut8 * bytes, ut64 sz, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd) {
	Sdb * sdb = bin->sdb;
	RBinPlugin *any = NULL, *plugin;
	RBinFile *binfile = R_NEW0 (RBinFile);
	RBinObject *o = NULL;
	RListIter *it;

	binfile->file = strdup (file);
	binfile->rawstr = rawstr;
	binfile->fd = fd;
	binfile->id = r_num_rand (4096);
	binfile->size = sz;

	if (bytes && sz > 0) {
		binfile->buf = r_buf_new ();
		r_buf_set_bytes (binfile->buf, bytes, sz);
	}

	if (!binfile->buf) {
		r_bin_file_free (binfile);
		return NULL;
	}

	binfile->curplugin = NULL;
	r_list_foreach (bin->plugins, it, plugin) {
		if (strncmp (plugin->name, "any", 5)==0) any = plugin;
		if ( plugin->check && plugin->check (binfile) ) {
			break;
		}
		// must be set to null
		plugin = NULL;
	}

	if (plugin == NULL) plugin = any;

	binfile->curplugin = plugin;
	if (plugin != any) 
		binfile->narch = 1;

	binfile->o = o = R_NEW0 (RBinObject);
	o->loadaddr = loadaddr;
	o->baddr = baseaddr;
	o->size = binfile->size;

	if (plugin->load && plugin->load (binfile)) {
		set_bin_items (binfile, plugin);
	}

	if (sdb) {
		char fdkey[128];
		snprintf (fdkey, sizeof (fdkey)-1, "fd.%i", fd);
		binfile->sdb = sdb_ns (sdb, fdkey);
		binfile->sdb_addrinfo = sdb_ns (binfile->sdb, "addrinfo");
		sdb_set (binfile->sdb, "archs", "0:0:x86:32", 0);
	}
	r_list_append (bin->binfiles, binfile);
	return binfile;
}

static int r_bin_file_load(RBin *bin, int rawstr, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd) {
	RListIter *it;
	RBinXtrPlugin *xtr;

	r_list_foreach (bin->binxtrs, it, xtr) {
		if (xtr->check && xtr->check (bin)) {
			if (xtr && (xtr->extractall_from_bytes || xtr->extract_from_bytes) )
				return r_bin_file_xtr_load (bin, xtr, baseaddr, loadaddr, xtr_idx, fd, rawstr);
			xtr = NULL;
			break;
		}
		xtr = NULL;
	}
	return r_bin_file_local_load (bin, NULL, rawstr, baseaddr, loadaddr, fd);
}

static int r_bin_file_local_load (RBin *bin, RBuffer *buf, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd) {
	RBinFile *binfile = NULL;

	if (buf && buf->buf) {
		binfile = r_bin_file_new (bin, bin->file, buf->buf, buf->length, rawstr, baseaddr, loadaddr, fd);
	} else {
		ut64 sz = 0;
		char *file_bytes = r_file_slurp (bin->file, (int*)&sz);
		if ((int)sz == -1) sz = UT64_MAX;
		if (file_bytes) {
			binfile = r_bin_file_new (bin, bin->file, (ut8*)file_bytes, sz, rawstr, baseaddr, loadaddr, fd);
		}
		free (file_bytes);
	}

	return r_bin_file_set_cur_binfile (bin, binfile);

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

R_API int r_bin_load(RBin *bin, const char *file, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd, int rawstr) {

	if (!bin || !file)
		return R_FALSE;

	bin->file = r_file_abspath (file);
	return r_bin_file_load (bin, rawstr, baseaddr, loadaddr, xtr_idx, fd);
}

R_API ut64 r_bin_get_baddr(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->baddr;
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
	if (o)
		return o->imports;
	return NULL;
}

R_API RBinInfo* r_bin_get_info(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (!o)
		return NULL;
	return o->info;
}

R_API RList* r_bin_get_libs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->libs;
	return NULL;
}

R_API RList* r_bin_get_relocs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->relocs;
	return NULL;
}

R_API RList* r_bin_get_sections(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->sections;
	return NULL;
}

R_API RBinSection* r_bin_get_section_at(RBin *bin, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;

	RBinObject *o = r_bin_cur_object (bin);
	if (o) {
		r_list_foreach (o->sections, iter, section) {
			from = va ? o->baddr+section->rva : section->offset;
			to = va ? o->baddr+section->rva+section->vsize :
					  section->offset + section->size;
			if (off >= from && off < to)
				return section;
		}
	}
	return NULL;
}

R_API RList* r_bin_reset_strings(RBin *bin) {
	RBinFile *a = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	if (!a || !o) return NULL;
	if (o->strings) {
		r_list_destroy (o->strings);
		o->strings = NULL;
	}

	if (bin->minstrlen <= 0)
		return NULL;

	if (a->curplugin && a->curplugin->strings)
		o->strings = a->curplugin->strings (a);
	else o->strings = get_strings (a, bin->minstrlen);
	return o->strings;
}

R_API RList* r_bin_get_strings(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->strings;
	return NULL;
}

R_API RList* r_bin_get_symbols(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->symbols;
	return NULL;
}

R_API int r_bin_is_big_endian (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return o->info->big_endian;
	return R_FALSE;
}

R_API int r_bin_is_stripped (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return R_BIN_DBG_STRIPPED (o->info->dbg_info);
	return 1;
}

R_API int r_bin_is_static (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o && r_list_length (o->libs)>0)
		return R_BIN_DBG_STATIC (o->info->dbg_info);
	return R_FALSE;
}

// TODO: Integrate with r_bin_dbg */
R_API int r_bin_has_dbg_linenums (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return R_BIN_DBG_LINENUMS (o->info->dbg_info);
	return R_FALSE;
}

R_API int r_bin_has_dbg_syms (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
		return R_BIN_DBG_SYMS (o->info->dbg_info);
	return R_FALSE;
}

R_API int r_bin_has_dbg_relocs (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o)
	return R_BIN_DBG_RELOCS (o->info->dbg_info);
	return R_FALSE;
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
	bin->minstrlen = -2;
	bin->cur = NULL;//R_NEW0 (RBinFile);
	//binfile->o = NULL;
#if 0
R_NEW0 (RBinObject);
	snprintf (fdkey, sizeof (fdkey)-1, "fd.%d", binfile->fd);
	binfile->sdb = sdb_ns (bin->sdb, fdkey);
	binfile->sdb_addrinfo = sdb_ns (binfile->sdb, "addrinfo");
#endif
	bin->binfiles = r_list_newf ((RListFree)r_bin_file_free);
	for (i=0; bin_static_plugins[i]; i++) {
		r_bin_add (bin, bin_static_plugins[i]);
	}
	bin->binxtrs = r_list_new ();
	bin->binxtrs->free = free;
	for (i=0; bin_xtr_static_plugins[i]; i++) {
		static_xtr_plugin = R_NEW (RBinXtrPlugin);
		*static_xtr_plugin = *bin_xtr_static_plugins[i];
		r_bin_xtr_add (bin, static_xtr_plugin);
	}
	return bin;
}

R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits, name);
	return binfile && r_bin_file_set_cur_binfile (bin, binfile);
}

R_API RBinFile * r_bin_file_find_by_arch_bits(RBin *bin, const char *arch, int bits, const char *name) {
	RListIter *iter;
	RBinInfo *info;
	RBinFile *binfile = NULL;
	RBinObject *o = NULL;

	if (!name || !arch) return NULL;

	r_list_foreach (bin->binfiles, iter, binfile) {
		o = binfile->o;
		info = o ? o->info : NULL;

		if ( info && !strcmp (info->arch, arch) &&
			bits != info->bits &&
			!strcmp (info->file, name))
			break;

		binfile = NULL;

	}
	return binfile;
}


R_API int r_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits, name);
	return binfile && r_bin_file_set_cur_binfile (bin, binfile);
}

R_API int r_bin_select_idx(RBin *bin, const char *name, int idx) {
	RBinFile *nbinfile = NULL, *binfile = r_bin_cur (bin);
	const char *tname = !name && binfile ? binfile->file : name;
	int res = R_FALSE;
	if (!tname || !bin) return res;
	nbinfile = r_bin_file_find_by_name_n (bin, tname, idx);
	return nbinfile && r_bin_file_set_cur_binfile (bin, nbinfile);
}

R_API void r_bin_list_archs(RBin *bin, int mode) {

	int i;
	char archline[128];
	RBinFile *binfile = r_bin_cur (bin);
	const char *name = binfile->file;
	int narch = binfile->narch;

	Sdb *binfile_sdb = binfile->sdb;
	if (!binfile_sdb) {
		eprintf ("Cannot find SDB!\n");
		return;
	} else if (!binfile) {
		eprintf ("Binary format not currently loaded!\n");
		return;
	}
	sdb_unset (binfile_sdb, ARCHS_KEY, 0);
	for (i = 0; i < narch; i++) {
		RBinFile *nbinfile = r_bin_file_find_by_name_n (bin, name, i);
		RBinObject *o = nbinfile ? nbinfile->o : NULL;
		RBinInfo *info = o ? o->info : NULL;

		if (info && narch > 1) {
			if (mode)
				printf ("%03i 0x%08"PFMT64x" %d %s_%i %s\n", i,
					o->boffset, o->size, info->arch,
					info->bits, info->machine);

			snprintf (archline, sizeof (archline)-1,
				"0x%08"PFMT64x":%d:%s:%d:%s",
				 o->boffset,
				 o->size,
				 info->arch,
				 info->bits,
				 info->machine);
			/// xxx machine not exported?
			//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
		} else {
			if (info) {
				if (mode)
					printf ("%03i 0x%08"PFMT64x" %d %s_%d\n", i,
						o->boffset, o->size,
						info->arch, info->bits);

				snprintf (archline, sizeof (archline),
					"0x%08"PFMT64x":%d:%s:%d",
					 o->boffset,
					 o->size,
					 info->arch,
					 info->bits);
			} else if (nbinfile && mode) {
				if (mode)
					printf ("%03i 0x%08"PFMT64x" %d unk_0\n", i,
						nbinfile->offset, nbinfile->size);

				snprintf (archline, sizeof (archline),
					"0x%08"PFMT64x":%d:%s:%d",
					 nbinfile->offset,
					 nbinfile->size, "unk", 0);
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
	if (a && a->curplugin && a->curplugin->get_offset)
		return a->curplugin->get_offset (a, type, idx);
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
	if (codelen<0) codelen = 0;
	if (datalen<0) datalen = 0;
	if (a && a->curplugin && a->curplugin->create)
		return a->curplugin->create (bin, code, codelen, data, datalen);
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
#warning TODO: add_field into class
	//eprintf ("TODO add field: %s \n", name);
}

R_API ut64 r_bin_get_offset (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	if (binfile) return binfile->offset;
	return UT64_MAX;
}

R_API ut64 r_bin_get_vaddr (RBin *bin, ut64 baddr, ut64 paddr, ut64 vaddr) {
	ut32 delta;
	RBinPlugin *cp = NULL;
	RBinFile *binfile = bin ? bin->cur : NULL;

	if (!binfile) return UT64_MAX;
	cp = binfile->curplugin;
	if (cp && cp->get_vaddr)
		return cp->get_vaddr (bin->cur, baddr, paddr, vaddr);
	if (!baddr) return vaddr;
 	delta = (paddr & 0xfffff000) | (vaddr & 0xfff);
	return baddr + delta;
}

R_API ut64 r_bin_get_size (RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) return o->size;
	return UT64_MAX;
}

R_API RBinFile * r_bin_file_find_by_fd (RBin *bin, ut32 bin_fd) {
	RListIter *iter;
	RBinFile *bf = NULL;

	if (!bin) return bf;
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->fd == bin_fd) break;
		bf = NULL;
	}
	return bf;
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

R_API int r_bin_file_set_cur_binfile (RBin * bin, RBinFile *bf) {
	if (bf) {
		bin->file = bf->file;
		bin->cur = bf;
		bin->narch = bf->narch;
		bin->minstrlen = bf->curplugin ? bf->curplugin->minstrlen : bin->minstrlen;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_bin_file_set_cur_by_name (RBin * bin, const char * name) {
	RBinFile *bf = r_bin_file_find_by_name (bin, name);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API RBinFile * r_bin_cur (RBin *bin) {
	if (bin) return bin->cur;
	return NULL;
}

R_API RBinObject * r_bin_cur_object (RBin *bin) {
	RBinFile *binfile = r_bin_cur (bin);
	if (binfile) return binfile->o;
	return NULL;
}
