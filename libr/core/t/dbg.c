#include <r_core.h>

int main() {
	RCore *core = r_core_new ();
	r_core_file_open (core, "dbg:///bin/ls", R_FALSE);
	r_core_cmd0(core, "e cfg.debug=true");
//	r_debug_use (&core->dbg, "native");
//	r_core_cmd0(core, "dpf");
//	r_core_cmd0(core, "dpf");
	r_core_cmd0(core, "dr");
	r_core_cmd0(core, ".dr*");
	r_core_cmd0(core, "px@esp");
	r_cons_flush();
}
