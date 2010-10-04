/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

/* TODO:
 * dlopen library and show address
 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_list.h>
#include <r_bin.h>
#include <list.h>
#include "../config.h"

static RBinPlugin *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS };
static RBinXtrPlugin *bin_xtr_static_plugins[] = { R_BIN_XTR_STATIC_PLUGINS };

static void get_strings_range(RBinArch *arch, RList *list, int min, ut64 from, ut64 to) {
	char str[R_BIN_SIZEOF_STRINGS];
	int i, matches = 0, ctr = 0;
	RBinString *ptr = NULL;

	for(i = from; i < to; i++) { 
		if ((IS_PRINTABLE (arch->buf->buf[i])) && matches < R_BIN_SIZEOF_STRINGS-1) {
			str[matches] = arch->buf->buf[i];
			matches++;
		} else {
			/* check if the length fits in our request */
			if (matches >= min) {
				if (!(ptr = R_NEW (RBinString))) {
					eprintf ("Error allocating string\n");
					break;
				}
				str[matches] = '\0';
				ptr->rva = ptr->offset = i-matches;
				ptr->size = matches;
				ptr->ordinal = ctr;
				// copying so many bytes here..
				memcpy (ptr->string, str, R_BIN_SIZEOF_STRINGS);
				ptr->string[R_BIN_SIZEOF_STRINGS-1] = '\0';
				r_list_append (list, ptr);
				ctr++;
			}
			matches = 0;
		}
	}
}

// TODO: check only in data section. filter chars only in -r mode
static RList* get_strings(RBinArch *arch, int min) {
	RList *ret;
	int count = 0;

	if (!(ret = r_list_new ())) {
		eprintf ("Error allocating array\n");
		return NULL;
	}
	ret->free = free;
	
	if (arch->sections) {
		RBinSection *section;
		RListIter *iter;
		r_list_foreach (arch->sections, iter, section) {
			// XXX: DIRTY HACK! should we check sections srwx to be READ ONLY and NONEXEC?
			if ((strstr (arch->info->bclass, "MACH0") && strstr (section->name, "_cstring")) || // OSX
				(strstr (arch->info->bclass, "ELF") && strstr (section->name, "data"))) { // LINUX
				count ++;
				get_strings_range (arch, ret, min, 
					section->offset, section->offset+section->size);
			}
		}	
	}
	if (count == 0)
		get_strings_range (arch, ret, min, 0, arch->size);
	return ret;
}

static int r_bin_init_items(RBin *bin, int dummy) {
	struct list_head *pos;
	RBinArch *arch = &bin->curarch;

	arch->curplugin = NULL;
	list_for_each (pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		if ((dummy && !strncmp (h->name, "dummy", 5)) || 
			(!dummy && (h->check && h->check (&bin->curarch)))) {
			bin->curarch.curplugin = h;
			break;
		}
	}
	if (!arch->curplugin || !arch->curplugin->load ||
		!arch->curplugin->load (arch))
		return R_FALSE;
	if (arch->curplugin->baddr)
		arch->baddr = arch->curplugin->baddr (arch);
	if (arch->curplugin->main)
		arch->main = arch->curplugin->main (arch);
	if (arch->curplugin->entries)
		arch->entries = arch->curplugin->entries (arch);
	if (arch->curplugin->fields)
		arch->fields = arch->curplugin->fields (arch);
	if (arch->curplugin->imports)
		arch->imports = arch->curplugin->imports (arch);
	if (arch->curplugin->info)
		arch->info = arch->curplugin->info (arch);
	if (arch->curplugin->libs)
		arch->libs = arch->curplugin->libs (arch);
	if (arch->curplugin->relocs)
		arch->relocs = arch->curplugin->relocs (arch);
	if (arch->curplugin->sections)
		arch->sections = arch->curplugin->sections (arch);
	if (arch->curplugin->strings)
		arch->strings = arch->curplugin->strings (arch);
	else arch->strings = get_strings (arch, 4);
	if (arch->curplugin->symbols)
		arch->symbols = arch->curplugin->symbols (arch);
	return R_TRUE;
}

/* TODO: Free plugins */
static void r_bin_free_items(RBin *bin) {
	RBinArch *arch = &bin->curarch;

	if (arch->entries)
		r_list_free (arch->entries);
	if (arch->fields)
		r_list_free (arch->fields);
	if (arch->imports)
		r_list_free (arch->imports);
	if (arch->info)
		free (arch->info);
	if (arch->libs)
		r_list_free (arch->libs);
	if (arch->relocs)
		r_list_free (arch->relocs);
	if (arch->sections)
		r_list_free (arch->sections);
	if (arch->strings)
		r_list_free (arch->strings);
	if (arch->symbols)
		r_list_free (arch->symbols);
	if (arch->main)
		free (arch->main);
	if (arch->file)
		free (arch->file);
	if (arch->curplugin && arch->curplugin->destroy)
		arch->curplugin->destroy (arch);
}

static void r_bin_init(RBin *bin) {
	struct list_head *pos;

	bin->curxtr = NULL;
	list_for_each (pos, &bin->binxtrs) {
		RBinXtrPlugin *h = list_entry (pos, RBinXtrPlugin, list);
		if (h->check && h->check (bin)) {
			bin->curxtr = h;
			break;
		}
	}
	if (bin->curxtr && bin->curxtr->load)
		bin->curxtr->load (bin);
}

static int r_bin_extract(RBin *bin, int idx) {
	ut8 *buf;
	int n = 1;

	if (bin->curxtr && bin->curxtr->extract)
		n = bin->curxtr->extract (bin, idx);
	else {
		bin->curarch.file = strdup (bin->file);
		if (!(buf = (ut8*)r_file_slurp (bin->file, &bin->curarch.size))) 
			return 0;
		bin->curarch.buf = r_buf_new ();
		if (!r_buf_set_bytes (bin->curarch.buf, buf, bin->curarch.size)) {
			free (buf);
			return 0;
		}
		free (buf);
	}
	return n;
}

R_API int r_bin_add(RBin *bin, RBinPlugin *foo) {
	struct list_head *pos;

	if (foo->init)
		foo->init (bin->user);
	list_for_each_prev (pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	}
	list_add_tail (&(foo->list), &(bin->bins));
	return R_TRUE;
}

R_API int r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo) {
	struct list_head *pos;

	if (foo->init)
		foo->init (bin->user);
	list_for_each_prev (pos, &bin->binxtrs) {
		RBinXtrPlugin *h = list_entry (pos, RBinXtrPlugin, list);
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	}
	list_add_tail (&(foo->list), &(bin->binxtrs));
	return R_TRUE;
}

R_API void* r_bin_free(RBin *bin) {
	if (!bin)
		return NULL;
	r_bin_free_items (bin);
	if (bin->curxtr && bin->curxtr->destroy)
		bin->curxtr->destroy (bin);
	free (bin);
	return NULL;
}

R_API int r_bin_list(RBin *bin) {
	struct list_head *pos;

	list_for_each_prev(pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		printf ("bin %-10s %s\n", h->name, h->desc);
	}
	list_for_each_prev(pos, &bin->binxtrs) {
		RBinXtrPlugin *h = list_entry (pos, RBinXtrPlugin, list);
		printf ("bin-xtr %-10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_bin_load(RBin *bin, const char *file, int dummy) {
	if (!bin || !file)
		return R_FALSE;
	bin->file = r_file_abspath (file);
	r_bin_init (bin);
	bin->narch = r_bin_extract (bin, 0);
	if (bin->narch == 0)
		return R_FALSE;
	return r_bin_init_items (bin, dummy);
}

// remove this getters.. we have no threads or mutexes to protect here
R_API ut64 r_bin_get_baddr(RBin *bin) {
	return bin->curarch.baddr;
}

R_API RBinAddr* r_bin_get_main(RBin *bin) {
	return bin->curarch.main;
}

R_API RList* r_bin_get_entries(RBin *bin) {
	return bin->curarch.entries;
}

R_API RList* r_bin_get_fields(RBin *bin) {
	return bin->curarch.fields;
}

R_API RList* r_bin_get_imports(RBin *bin) {
	return bin->curarch.imports;
}

R_API RBinInfo* r_bin_get_info(RBin *bin) {
	return bin->curarch.info;
}

R_API RList* r_bin_get_libs(RBin *bin) {
	return bin->curarch.libs;
}

R_API RList* r_bin_get_relocs(RBin *bin) {
	return bin->curarch.relocs;
}

R_API RList* r_bin_get_sections(RBin *bin) {
	return bin->curarch.sections;
}

R_API RBinSection* r_bin_get_section_at(RBin *bin, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;

	if (bin->curarch.sections)
	r_list_foreach (bin->curarch.sections, iter, section) {
		from = va ? bin->curarch.baddr+section->rva : section->offset;
		to = va ? bin->curarch.baddr+section->rva+section->vsize :
				  section->offset + section->size;
		if (off >= from && off < to)
			return section;
	}
	return NULL;
}

R_API RList* r_bin_get_strings(RBin *bin) {
	return bin->curarch.strings;
}

R_API RList* r_bin_get_symbols(RBin *bin) {
	return bin->curarch.symbols;
}

R_API int r_bin_is_big_endian (RBin *bin) {
	return bin->curarch.info->big_endian;
}

R_API int r_bin_is_stripped (RBin *bin) {
	return R_BIN_DBG_STRIPPED (bin->curarch.info->dbg_info);
}

R_API int r_bin_is_static (RBin *bin) {
	return R_BIN_DBG_STATIC (bin->curarch.info->dbg_info);
}

/* XXX Implement in r_bin_meta and deprecate? */
R_API int r_bin_has_dbg_linenums (RBin *bin) {
	return R_BIN_DBG_LINENUMS (bin->curarch.info->dbg_info);
}

R_API int r_bin_has_dbg_syms (RBin *bin) {
	return R_BIN_DBG_SYMS (bin->curarch.info->dbg_info);
}

R_API int r_bin_has_dbg_relocs (RBin *bin) {
	return R_BIN_DBG_RELOCS (bin->curarch.info->dbg_info);
}

R_API RBin* r_bin_new() {
	RBin *bin; 
	RBinPlugin *static_plugin;
	RBinXtrPlugin *static_xtr_plugin;
	int i;

	bin = R_NEW (RBin);
	if (bin) {
		memset (bin, 0, sizeof (RBin));
		INIT_LIST_HEAD (&bin->bins);
		for (i=0; bin_static_plugins[i]; i++) {
			static_plugin = R_NEW (RBinPlugin);
			memcpy (static_plugin, bin_static_plugins[i], sizeof (RBinPlugin));
			r_bin_add (bin, static_plugin);
		}
		INIT_LIST_HEAD (&bin->binxtrs);
		for (i=0; bin_xtr_static_plugins[i]; i++) {
			static_xtr_plugin = R_NEW (RBinXtrPlugin);
			memcpy (static_xtr_plugin, bin_xtr_static_plugins[i], sizeof (RBinXtrPlugin));
			r_bin_xtr_add (bin, static_xtr_plugin);
		}
	}
	return bin;
}

R_API int r_bin_set_arch(RBin *bin, const char *arch, int bits, const char *name) {
	int i;

	for (i = 0; i < bin->narch; i++) {
		r_bin_set_archidx (bin, i);
		if (!bin->curarch.info || !bin->curarch.file ||
			(arch && !strstr (bin->curarch.info->arch, arch)) ||
			(bits && bits != bin->curarch.info->bits) ||
			(name && !strstr (bin->curarch.file, name)))
			continue;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_bin_set_archidx(RBin *bin, int idx) {
	r_bin_free_items (bin);
	if (r_bin_extract (bin, idx))
		return r_bin_init_items (bin, R_FALSE);
	return R_FALSE;
}

R_API void r_bin_list_archs(RBin *bin) {
	int i;

	for (i = 0; i < bin->narch; i++)
		if (r_bin_set_archidx (bin, i) && bin->curarch.info)
			printf ("%03i %s %s_%i (%s)\n", i, bin->curarch.file,
					bin->curarch.info->arch, bin->curarch.info->bits,
					bin->curarch.info->machine);
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}
