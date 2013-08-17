/* lua extension for libr (radare2) - 2013 - pancake */

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define LIBDIR PREFIX"/lib"

static lua_State *L;
static RCore* core = NULL;
static int lua_run(RLang *lang, const char *code, int len);

static int r_lang_lua_report (lua_State *L, int status) {
	const char *msg;
	if (status) {
		msg = lua_tostring(L, -1);
		if (msg == NULL) msg = "(error with no message)";
		eprintf ("status=%d, %s\n", status, msg);
		lua_pop (L, 1);
	}
	return status;
}

static int r_lua_file(void *user, const char *file) {
	int status = luaL_loadfile (L, file);
	if (status)
		return r_lang_lua_report (L,status);
	status = lua_pcall (L,0,0,0);
	if (status)
		return r_lang_lua_report (L,status);
	return 0;
}

static int lua_cmd_str(lua_State *L) {
	char *str;
	const char *s = lua_tostring(L, 1);  /* get argument */
	str = r_core_cmd_str (core, s);
	lua_pushstring (L, str);  /* push result */
	free (str);
	return 1;  /* number of results */
}

static int lua_cmd (lua_State *L) {
	const char *s = lua_tostring(L, 1);  /* get argument */
	lua_pushnumber (L, r_core_cmd (core, s, 0));  /* push result */
	return 1;  /* number of results */
}

#define lua_open()  luaL_newstate()

static int init(RLang *lang) {
	char a[128];
 	L = (lua_State*)lua_open();
	if (L==NULL) {
		printf("Exit\n");	
		return 0;
	}

	lua_gc (L, LUA_GCSTOP, 0);
	luaL_openlibs (L);
	luaopen_base (L);
	luaopen_string (L);
	//luaopen_io(L); // PANIC!!
	lua_gc (L, LUA_GCRESTART, 0);

	lua_pushlightuserdata (L, lang->user);
	lua_setglobal (L, "core");

	lua_register (L, "cmd_str", &lua_cmd_str);
	lua_pushcfunction(L, lua_cmd_str);
	lua_setglobal(L,"cmd_str");

	// DEPRECATED: cmd = radare_cmd_str
	lua_register(L, "cmd", &lua_cmd);
	lua_pushcfunction(L,lua_cmd);
	lua_setglobal(L,"cmd");

	lua_run (lang, "require \"r_core\"", 0);
	sprintf (a, "c=r_core.RCore_ncast(0x%"PFMT64x")",
		(ut64)(size_t)(void*)core);
	lua_run (lang, a, 0);

	//-- load template
	r_lua_file (NULL, LIBDIR"/radare2/"R2_VERSION"/radare.lua");
	fflush(stdout);

	return R_TRUE;
}

static int lua_run(RLang *lang, const char *code, int len) {
	core = lang->user; // XXX buggy?
	if (len == 0) len = strlen (code);
	luaL_loadbuffer (L, code, len, ""); // \n included
	if (lua_pcall (L, 0, 0, 1) != 0) {
		eprintf ("syntax error: %s\n",
                 lua_tostring(L, -1));
	}
	clearerr (stdin);
	//lua_close(L); // TODO
	return R_TRUE;
}

static struct r_lang_plugin_t r_lang_plugin_lua = {
	.name = "lua",
	.ext = "lua",
	.desc = "LUA language extension",
	.help = NULL,
	.run = lua_run,
	.init = (void*)init,
	.run_file = (void*)r_lua_file,
	.set_argv = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_LANG,
	.data = &r_lang_plugin_lua,
};
#endif
