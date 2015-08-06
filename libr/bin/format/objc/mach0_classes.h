#include <r_bin.h>

#undef Mach0_class_
#undef Mach0_struct_
#undef mach0_ut
#undef r_bin_plugin_mach

#ifdef R_MACH0_CLASS64
#define Mach0_class_(name) Mach0_class64_##name
#define Mach0_struct_(name) struct Mach0_struct64_##name
#define mach0_ut ut64
#define r_bin_plugin_mach r_bin_plugin_mach064
#else
#define Mach0_class_(name) Mach0_class32_##name
#define Mach0_struct_(name) struct Mach0_struct32_##name
#define mach0_ut ut32
#define r_bin_plugin_mach r_bin_plugin_mach0
#endif

#ifndef MACH0_CLASSES_H
#define MACH0_H

RList* Mach0_class_(get_classes)(RBinFile *arch);

#endif // MACH0_CLASSES_H
