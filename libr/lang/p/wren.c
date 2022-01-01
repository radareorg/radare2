/* radare - LGPL - Copyright 2018-2022 pancake */

#include <r_lib.h>
#include <r_core.h>
#include <r_lang.h>
#include "wren-vm.h"
#include "wren-vm.c"
#include "json-wren.h"

static const char *r2_wren =
"class R2 {\n"
"	foreign static cmd(str)\n"
"	static cmdj(str) {\n"
"		var res = R2.cmd(str)\n"
"		return Json.parse(res)\n"
"	}\n"
"}\n";

static WrenVM* vm = NULL;

static bool lang_wren_file(RLang *lang, const char *file) {
	char * code = r_file_slurp (file, NULL);
	if (code) {
		WrenInterpretResult result = wrenInterpret (vm, "main", code);
		if (result != WREN_RESULT_SUCCESS) {
			eprintf ("wren: Error loading script\n");
		}
		free (code);
	} else {
		eprintf ("file not found (%s)\n", file);
		return false;
	}
	return true;
}

static void writeFn(WrenVM* vm, const char* text) {
	// r_cons_printf ("%s", text);
	printf("%s", text);
}

void errorFn(WrenVM* vm, WrenErrorType errorType, const char* module, const int line, const char* msg) {
	switch (errorType) {
	case WREN_ERROR_COMPILE:
		eprintf("[%s line %d] [Error] %s\n", module, line, msg);
		break;
	case WREN_ERROR_STACK_TRACE:
		eprintf("[%s line %d] in %s\n", module, line, msg);
		break;
	case WREN_ERROR_RUNTIME:
		eprintf("[Runtime Error] %s\n", msg);
		break;
	}
}

static RLang *lang = NULL;

void r2cmd(WrenVM* vm) {
	const char *a = wrenGetSlotString (vm, 1);
	if (a && lang->cmd_str) {
		char *res = lang->cmd_str (lang->user, a);
		wrenSetSlotString(vm, 0, res);
		free (res);
	}
}

WrenForeignMethodFn foreign_methods (struct WrenVM* vm,
		const char* module,
		const char* className,
		bool isStatic,
		const char* signature
		) {
	if (!strcmp (module, "main") && !strcmp (className, "R2") && isStatic) {
		if (!strcmp (signature, "cmd(_)")) {
			return r2cmd;
		}
	}
	return NULL;
}

static WrenLoadModuleResult load_module(WrenVM* vm, const char* name) {
	// TODO: add include paths
#if 0
	char *res = r_file_slurp (name, NULL);
#endif
	WrenLoadModuleResult wmr = {0};
	return wmr;
}

static bool lang_wren_init(void *user) {
	// wrenFreeVM(vm);
	lang = user;
	WrenConfiguration config;
	wrenInitConfiguration (&config);
	config.writeFn = &writeFn;
	config.errorFn = &errorFn;
	config.bindForeignMethodFn = foreign_methods;
	config.loadModuleFn = load_module;
	vm = wrenNewVM (&config);
	WrenInterpretResult result = wrenInterpret (vm, "main", json_wren);
	if (result != WREN_RESULT_SUCCESS) {
		eprintf ("wren cannot load json%c", 10);
	}
	result = wrenInterpret (vm, "main", r2_wren);
	if (result != WREN_RESULT_SUCCESS) {
		eprintf ("wren cannot load json%c", 10);
	}
	eprintf ("wren vm init%c", 10);
	return true;
}

static bool lang_wren_run(RLang *lang, const char *code, int len) {
	WrenInterpretResult result = wrenInterpret(vm, "main", code);
	return (result == WREN_RESULT_SUCCESS);
}

static RLangPlugin r_lang_plugin_wren = {
	.name = "wren",
	.ext = "wren",
	.license = "MIT",
	.desc = "wren.io scripting language",
	.run = lang_wren_run,
	.init = (void*)lang_wren_init,
	.run_file = (void*)lang_wren_file,
};
