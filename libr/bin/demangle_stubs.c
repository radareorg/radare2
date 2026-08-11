/* radare - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>

#ifndef R_BIN_DEMANGLE_JAVA
R_API char *r_bin_demangle_java(const char *str) {
	(void)str;
	return NULL;
}
#endif

#ifndef R_BIN_DEMANGLE_PASCAL
R_API char *r_bin_demangle_freepascal(const char *str) {
	(void)str;
	return NULL;
}
#endif

#ifndef R_BIN_DEMANGLE_CXX
R_API char *r_bin_demangle_cxx(RBinFile *bf, const char *str, ut64 vaddr) {
	(void)bf;
	(void)str;
	(void)vaddr;
	return NULL;
}
#endif

#ifndef R_BIN_DEMANGLE_MSVC
R_API char *r_bin_demangle_msvc(const char *str) {
	(void)str;
	return NULL;
}
#endif

#ifndef R_BIN_DEMANGLE_SWIFT
R_API char *r_bin_demangle_swift(const char *str, bool syscmd, bool trylib) {
	(void)str;
	(void)syscmd;
	(void)trylib;
	return NULL;
}
#endif

#ifndef R_BIN_DEMANGLE_OBJC
R_API char *r_bin_demangle_objc(RBinFile *bf, const char *str) {
	(void)bf;
	(void)str;
	return NULL;
}
#endif

#ifndef R_BIN_DEMANGLE_RUST
R_API char *r_bin_demangle_rust(RBinFile *bf, const char *str, ut64 vaddr) {
	(void)bf;
	(void)str;
	(void)vaddr;
	return NULL;
}
#endif

#ifndef R_BIN_DEMANGLE_DLANG
R_API char *r_bin_demangle_dlang(const char *str) {
	(void)str;
	return NULL;
}
#endif

#ifndef R_BIN_DEMANGLE_IBMXL
R_API char *r_bin_demangle_ibmxl(const char *str) {
	(void)str;
	return NULL;
}
#endif
