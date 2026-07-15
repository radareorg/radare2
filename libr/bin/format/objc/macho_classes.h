#include <r_bin.h>

#include "macho/macho_specs.h"
#include "macho/macho.h"

#undef macho_ut
#undef r_bin_plugin_mach

#ifdef R_BIN_MACHO64
#define macho_ut ut64
#define r_bin_plugin_mach r_bin_plugin_macho64
#else
#define macho_ut ut32
#define r_bin_plugin_mach r_bin_plugin_macho
#endif

#ifndef MACHO_CLASSES_H
#define MACHO_CLASSES_H

R_API RList *MACHO_(parse_classes)(RBinFile *bf, objc_cache_opt_info *oi);
R_API void MACHO_(get_class_t)(RBinFile *bf, RBinClass *klass, macho_ut p, bool dupe, const RSkipList *relocs, objc_cache_opt_info *oi);
R_API void MACHO_(get_category_t)(RBinFile *bf, RBinClass *klass, macho_ut p, const RSkipList *relocs, objc_cache_opt_info *oi);

#endif // MACHO_CLASSES_H
