#ifndef _BIN_PRIVATE_H_
#define _BIN_PRIVATE_H_

#include <r_bin.h>
#include <r_util.h>
#include <r_types.h>

RBinFile *r_bin_file_new(RBin *bin, const char *file, const ut8 *bytes, ut64 sz, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr);
RBinFile *r_bin_file_new_from_bytes(RBin *bin, const char *file, const ut8 *bytes, ut64 sz, ut64 file_sz, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname, const char *xtrname, ut64 offset, bool steal_ptr);
RBinFile *r_bin_file_new_from_fd(RBin *bin, int fd, RBinFileOptions *options);
RBinObject *r_bin_file_object_find_by_id(RBinFile *binfile, ut32 binobj_id);
RList *r_bin_file_get_strings(RBinFile *a, int min, int dump, int raw);
void r_bin_file_get_strings_range(RBinFile *bf, RList *list, int min, int raw, ut64 from, ut64 to);
RBinFile *r_bin_file_find_by_object_id(RBin *bin, ut32 binobj_id);
RBinFile *r_bin_file_find_by_id(RBin *bin, ut32 binfile_id);
int r_bin_file_object_add(RBinFile *binfile, RBinObject *o);
RBinFile *r_bin_file_find_by_name_n(RBin *bin, const char *name, int idx);
bool r_bin_file_set_cur_binfile_obj(RBin *bin, RBinFile *bf, RBinObject *obj);
int r_bin_file_ref(RBin *bin, RBinFile *a);
RBinFile *r_bin_file_create_append(RBin *bin, const char *file, const ut8 *bytes, ut64 sz, ut64 file_sz, int rawstr, int fd, const char *xtrname, bool steal_ptr);
RBinFile *r_bin_file_xtr_load_bytes(RBin *bin, RBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
bool r_bin_file_set_bytes(RBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr);
int r_bin_file_ref_by_bind(RBinBind *binb);

void r_bin_section_free(RBinSection *bs);

void r_bin_object_free(void /*RBinObject*/ *o_);
ut64 r_bin_object_get_baddr(RBinObject *o);
void r_bin_object_filter_strings(RBinObject *bo);
void r_bin_object_set_baddr(RBinObject *o, ut64 baddr);
RBinObject *r_bin_object_new(RBinFile *binfile, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz);
RBinObject *r_bin_object_get_cur(RBin *bin);
RBinObject *r_bin_object_find_by_arch_bits(RBinFile *binfile, const char *arch, int bits, const char *name);
void r_bin_object_delete_items(RBinObject *o);

const char *r_bin_lang_tostring(int lang);
int r_bin_lang_type(RBinFile *binfile, const char *def, const char *sym);
bool r_bin_lang_swift(RBinFile *binfile);

RBinClass *r_bin_class_get(RBinFile *binfile, const char *name);
RBinClass *r_bin_class_new(RBinFile *binfile, const char *name, const char *super, int view);
void r_bin_class_free(RBinClass *c);
RBinSymbol *r_bin_class_add_method(RBinFile *binfile, const char *classname, const char *name, int nargs);
void r_bin_class_add_field(RBinFile *binfile, const char *classname, const char *name);
RList *r_bin_classes_from_symbols(RBinFile *bf, RBinObject *o);

#endif
