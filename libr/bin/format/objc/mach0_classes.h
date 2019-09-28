#include <r_bin.h>

#include "mach0/mach0_specs.h"
#include "mach0/mach0.h"

#undef mach0_ut
#undef r_bin_plugin_mach

#ifdef R_BIN_MACH064
#define mach0_ut ut64
#define r_bin_plugin_mach r_bin_plugin_mach064
#else
#define mach0_ut ut32
#define r_bin_plugin_mach r_bin_plugin_mach0
#endif

#ifndef MACH0_CLASSES_H
#define MACH0_CLASSES_H

R_API RList *MACH0_(parse_classes)(RBinFile *bf);
R_API void MACH0_(get_class_t)(mach0_ut p, RBinFile *bf, RBinClass *klass, bool dupe, RSkipList *relocs);
R_API void MACH0_(get_category_t)(mach0_ut p, RBinFile *bf, RBinClass *klass, RSkipList *relocs);

#endif // MACH0_CLASSES_H
