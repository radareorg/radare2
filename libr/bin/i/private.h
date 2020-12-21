#ifndef R_BIN_PRIVATE_H_
#define R_BIN_PRIVATE_H_

#include <r_bin.h>
#include <r_util.h>
#include <r_types.h>

R_IPI RBinFile *r_bin_file_new(RBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr);
R_IPI RBinObject *r_bin_file_object_find_by_id(RBinFile *binfile, ut32 binobj_id);
R_IPI RList *r_bin_file_get_strings(RBinFile *a, int min, int dump, int raw);
R_IPI RBinFile *r_bin_file_find_by_object_id(RBin *bin, ut32 binobj_id);
R_IPI RBinFile *r_bin_file_find_by_id(RBin *bin, ut32 binfile_id);
R_IPI bool r_bin_file_set_obj(RBin *bin, RBinFile *bf, RBinObject *obj);
R_IPI RBinFile *r_bin_file_xtr_load_bytes(RBin *bin, RBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
R_IPI bool r_bin_file_set_bytes(RBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr);

R_IPI RBinPlugin *r_bin_get_binplugin_any(RBin *bin);
R_IPI RBinXtrPlugin *r_bin_get_xtrplugin_by_name(RBin *bin, const char *name);
R_IPI RBinPlugin *r_bin_get_binplugin_by_name(RBin *bin, const char *name);

R_IPI void r_bin_section_free(RBinSection *bs);

R_IPI void r_bin_object_free(void /*RBinObject*/ *o_);
R_IPI ut64 r_bin_object_get_baddr(RBinObject *o);
R_IPI void r_bin_object_filter_strings(RBinObject *bo);
R_IPI RBinObject *r_bin_object_new(RBinFile *binfile, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz);
R_IPI RBinObject *r_bin_object_get_cur(RBin *bin);
R_IPI RBinObject *r_bin_object_find_by_arch_bits(RBinFile *binfile, const char *arch, int bits, const char *name);
R_IPI RBNode *r_bin_object_patch_relocs(RBin *bin, RBinObject *o);

R_IPI const char *r_bin_lang_tostring(int lang);
R_IPI int r_bin_lang_type(RBinFile *binfile, const char *def, const char *sym);
R_IPI bool r_bin_lang_swift(RBinFile *binfile);

R_IPI void r_bin_class_free(RBinClass *c);
R_IPI RBinSymbol *r_bin_class_add_method(RBinFile *binfile, const char *classname, const char *name, int nargs);
R_IPI void r_bin_class_add_field(RBinFile *binfile, const char *classname, const char *name);

R_IPI RBinFile *r_bin_file_xtr_load_buffer(RBin *bin, RBinXtrPlugin *xtr, const char *filename, RBuffer *buf, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
R_IPI RBinFile *r_bin_file_new_from_buffer(RBin *bin, const char *file, RBuffer *buf, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname);
#endif
