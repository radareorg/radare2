#include <r_crypto.h>

struct r_crypto_handle_t raes_crypto_plugin_aes = { 
        .name = "crypto_aes",
	/* TODO */
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = { 
        .type = R_LIB_TYPE_CRYPTO,
        .data = &r_crypto_plugin_aes
};
#endif

