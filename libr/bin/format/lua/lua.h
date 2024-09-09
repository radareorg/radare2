/* radare - LGPL - Copyright 2024-2024 - bemodtwz */
#include "lua_spec.h"
#include <r_bin.h>

bool check_header(RBuffer *b);
void lua_header_free(RLuaHeader *lhead);
RLuaHeader *r_lua_load_header(RBuffer *b);
