/* radare2 - LGPL - Copyright 2018 - pancake */

#include <r_bin.h>

R_API bool r_bin_loader(RBin *bin, ut32 boid, int options) {
	// uses a plugin from bin.loader eval var and loads the selected binobj
	// options must be used to specify if we want to load the libraries of the libraries recursively
	// or resolve the PLT from the binary or not
	// this requires io.cache
	return false;
}

R_API bool r_bin_loader_library(RBin *bin, const char *name, int options) {
	// options specify if we want to resolve the symbols and fill the PLT
	// this is obviously a problem if we have multiple libs that depend
	// on symbols recursively, and that's where the LD_BIND_NOW option comes to the action
	// the plt must be modified by using io.cache writes
	return false;
}

R_API bool r_bin_loader_option(RBin *bin, const char *key, const char *data) {
	// key value storage to specify LD_LIBRARY_PATH LD_BIND_NOW and other useful options
	// RCore or radare2 can set those vars from the environment if desired
	return false;
}

R_API bool r_bin_loader_unload(RBin *bin) {
	// unload all libraries and drop PLT changes
	return false;
}
