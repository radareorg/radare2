#if R_INCLUDE_BEGIN

#if 0
https://opensource.apple.com/source/xnu/xnu-201/osfmk/vm/vm_debug.c
#endif

static RCoreHelpMessage help_dmh_macos = {
	"Usage:", " dmh[?]", " # debug memory heap",
	"dmh", "", "List process memory zones",
	NULL
};

static void macos_list_heaps(RCore *core, const char format) {
	int pid = core->dbg->pid;
	if (pid < 0 || !r_config_get_b (core->config, "cfg.debug")) {
		return;
	}
	// -interleaved
	if (format == '*') {
		char *s = r_sys_cmd_strf ("for kv in `vmmap -interleaved -purge -w %d | grep 0x | grep -v MALLOC | grep -v Load | sed -e 's,_0x,=0x,g' -e 's,_, ,g' | awk '{print $1}'`; do echo \"f heap.$kv\"; done", pid);
		r_kons_printf (core->cons, "%s\n", s);
		free (s);
	} else {
		char *s = r_sys_cmd_strf ("vmmap -interleaved -purge -w %d | grep -e 0x -e MALLOC | sed -e 's,_0x,=0x,g' -e 's,_, ,g'", pid);
		r_kons_printf (core->cons, "%s\n", s);
		free (s);
	}
}

static int dmh_macos(RCore *core, const char *input) {
	switch (input[0]) {
	case '?': // dmh?
		r_core_cmd_help (core, help_dmh_macos);
		break;
	case 0:
	case ' ':
	case '*':
	case 'j':
		macos_list_heaps (core, input[0]);
		break;
	default:
		R_LOG_ERROR ("Invalid subcommand. See dmh[bj]");
		break;
	}
	return 0;
}

#endif
