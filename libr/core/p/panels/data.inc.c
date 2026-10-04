/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

// clang-format off

static const char *panels_dynamic[] = {
	"Disassembly", "Stack", "Registers"
};

static const char *panels_static[] = {
	"Disassembly", "Functions", "Symbols"
};

static const char *menus[] = {
	"File", "Edit", "View", "Analyze", "Search", "Debug", "Tools", "Help"
};

static const char *menus_desc[] = {
	"File and project operations",
	"Clipboard and write operations",
	"Open analysis and data views",
	"Core analysis actions and plugin commands",
	"String, code and pattern searches",
	"Execution, breakpoints and emulation",
	"Tools, shells and file manager",
	"Help, versions and manpages"
};

static const char *menus_File[] = {
	"New", "Open File", "Reopen...", "Close File", "--", "Open Project", "Save Project", "Close Project", "--", "Quit"
};

static const char *menus_Settings[] = {
	"Edit radare2rc", "--", "Color Themes...", "Decompiler...", "Disassembly...", "Screen...", "--",
	"Save Layout", "Load Layout", "Clear Saved Layouts"
};

static const char *menus_ReOpen[] = {
	"In Read+Write", "In Debugger"
};

static const char *menus_loadLayout[] = {
	"Saved..", "Default"
};

static const char *menus_Edit[] = {
	"Settings", "--",
	"Copy", "Paste", "Clipboard", "Write String", "Write Hex", "Write Value", "Assemble", "Fill", "io.cache"
};

static const char *menus_iocache[] = {
	"On", "Off"
};

static const char *menus_View_Code[] = {
	"Disassembly", "Function Disassembly", "Disassembly Summary", "Decompiler", "Decompiler With Offsets",
	"Graph", "Tiny Graph", "Show All Decompiler Output"
};

static const char *menus_View_Data[] = {
	"Hexdump", "Hexdump References", "Clipboard", "Strings in data sections", "Strings in the whole bin",
	"Entropy", "Entropy Fire"
};

static const char *menus_View_Metadata[] = {
	"Comments", "Flags", "Flag Spaces", "Visual Marks", "Types", "Structures", "Enumerations", "Function Signatures"
};

static const char *menus_View_Binary[] = {
	"Info", "Headers", "Sections", "Segments", "Entry Points", "Symbols", "Imports", "Exports",
	"Relocs", "Libraries", "Classes", "Methods", "Resources", "File Hashes"
};

static const char *menus_View_Analysis[] = {
	"Functions", "Function Info", "Function Calls", "Basic Blocks", "Function Variables",
	"Variable Reads", "Variable Writes", "Xrefs", "Xrefs Here", "Xrefs To", "References From"
};

static const char *menus_View_Debug[] = {
	"Registers", "Register Columns", "Register References", "Flag Registers (1 bit)",
	"Debug Registers", "FPU Registers", "XMM Registers", "YMM Registers", "--",
	"Backtrace", "Stack", "Locals", "Breakpoints", "Memory Maps", "Modules", "Threads", "Processes"
};

static const char *menus_View_Other[] = {
	"Console", "Open Files", "IO Maps", "Database"
};

static const char *menus_Tools[] = {
	"Calculator", "Assembler",
	"--",
	"R2 Shell", "System Shell", "FSMount Shell", "R2JS Shell",
	"--",
	"File Manager"
};

static const char *menus_Search[] = {
	"String (Whole Bin)", "String (Data Sections)", "Assembly Strings", "Syscalls", "Magic", "ROP", "Code", "Hexpairs"
};

static const char *menus_Emulate[] = {
	"Step From", "Step To", "Step Range"
};

static const char *menus_Debug[] = {
	"Continue", "Step", "Step Over", "Toggle Breakpoint", "Add Watchpoint", "Reload"
};

static const char *menus_Analyze[] = {
	"Function", "Symbols", "Program", "BasicBlocks", "Calls", "Preludes", "References", "Plugins..."
};

static const char *menus_settings_disassembly[] = {
	"asm", "hex.section", "io.cache", "hex.pairs", "emu.str"
};

static const char *menus_settings_disassembly_asm[] = {
	"asm.bytes", "asm.section", "asm.cmt.right", "asm.emu", "asm.var.summary",
	"asm.pseudo", "asm.flags.inbytes", "asm.arch", "asm.bits", "asm.cpu"
};

static const char *menus_settings_screen[] = {
	"scr.bgfill", "scr.color", "scr.utf8", "scr.utf8.curvy", "scr.wheel"
};

static const char *menus_Help[] = {
	"Toggle Help",
	"Manpages...",
	"--",
	"License", "Version", "Full Version",
	"--",
	"Fortune", "2048"
};

static const char *entropy_rotate[] = {
	"", "2", "b", "c", "d", "e", "F", "i", "j", "m", "p", "s", "z", "0"
};

static char *hexdump_rotate[] = {
	"xc", "pxa", "pxr", "prx", "pxb", "pxh", "pxw", "pxq", "pxd", "pxr"
};

static const char *register_rotate[] = {
	"", "=", "r", "??", "C", "i", "o"
};

static const char *function_rotate[] = {
	"l", "i", "x"
};

static const char *cache_white_list_cmds[] = {
	"agf", "Help", "is,"
};

static RotateEntry rotate_entries[8];
static int n_rotate_entries;

static ModalEntry *modal_entries;
static int n_modal_entries;

static RCoreHelpMessage help_msg_panels = {
	"|",        "split current panel vertically",
	"-",        "split current panel horizontally",
	":",        "run r2 command in prompt",
	";",        "add/remove comment",
	"_",        "show hud",
	"\\",       "show user-friendly hud",
	"?",        "show this help",
	"!",        "swap into visual mode",
	".",        "seek to PC or entrypoint",
	"*",        "show decompiler in the current panel",
	"\"",       "create a panel from the list and replace the current one",
	"/",        "highlight the keyword",
	"(",        "toggle snow",
	"&",        "toggle cache for the current panel",
	"=",        "open the menu of the current panel (maximize, contents, cache, close)",
	"[1-9]",    "follow jmp/call identified by shortcut (like ;[1])",
	"' '",      "(space) toggle graph / panels",
	"tab",      "go to the next panel",
	"Enter",    "maximize current panel in zoom mode",
	"a",        "toggle auto update for decompiler",
	"b",        "browse symbols, flags, configurations, classes, ...",
	"c",        "toggle cursor",
	"C",        "toggle color",
	"d",        "define in the current address. Same as Vd",
	"D",        "show disassembly in the current panel",
	"e",        "change title and command of current panel",
	"E",        "edit color theme",
	"f",        "set/add filter keywords",
	"F",        "remove all the filters",
	"g",        "go/seek to given offset",
	"G",        "go/seek to highlight",
	"i",        "overwrite bytes at the cursor or start of the selection",
	"I",        "insert assembly",
	"Mouse",    "click a byte to select it, drag to select a range, right-click for panel settings",
	"Scrollbar", "click or drag the right-side scrollbar of cached contents",
	"`",        "rotate between common disassembly / hexdump options",
	"hjkl",     "move around (left-down-up-right)",
	"HJKL",     "move around (left-down-up-right) by page",
	"m",        "select the menu panel",
	"M",        "open new custom frame",
	"n/N",      "seek next/prev function/flag/hit (scr.nkey)",
	"p/P",      "rotate panel layout",
	"q",        "quit, or close a tab",
	"Q",        "close all the tabs and quit",
	"r",        "toggle callhints/jmphints/leahints",
	"R",        "randomize color palette (ecr)",
	"s/S",      "step in / step over",
	"t/T",      "tab menu (t1..t9 switch tab) / close a tab",
	"u/U",      "undo / redo seek",
	"w",        "shuffle panels around in window mode",
	"V",        "go to the graph mode",
	"x",        "show xrefs/refs of current function from/to data/code",
	"X",        "close current panel",
	"z",        "swap current panel with the first one",
	NULL
};

static RCoreHelpMessage help_msg_panels_window = {
	":",        "run r2 command in prompt",
	";",        "add/remove comment",
	"\"",       "create a panel from the list and replace the current one",
	"?",        "show this help",
	"|",        "split the current panel vertically",
	"-",        "split the current panel horizontally",
	"tab",      "go to the next panel",
	"Enter",    "maximize current panel in zoom mode",
	"d",        "define in the current address. Same as Vd",
	"b",        "browse symbols, flags, configurations, classes, ...",
	"hjkl",     "move around (left-down-up-right)",
	"HJKL",     "resize panels vertically/horizontally",
	"Q/q/w",    "quit window mode",
	"p/P",      "rotate panel layout",
	"t/T",      "rotate related commands in a panel",
	"X",        "close current panel",
	NULL
};

static RCoreHelpMessage help_msg_panels_zoom = {
	"?",        "show this help",
	":",        "run r2 command in prompt",
	";",        "add/remove comment",
	"\"",       "create a panel from the list and replace the current one",
	"' '",      "(space) toggle graph / panels",
	"=",        "open the menu of the current panel",
	"m",        "select the menu bar",
	"tab",      "go to the next panel",
	"b",        "browse symbols, flags, configurations, classes, ...",
	"d",        "define in the current address. Same as Vd",
	"c",        "toggle cursor",
	"C",        "toggle color",
	"hjkl",     "move around (left-down-up-right)",
	"p/P",      "seek to next or previous scr.nkey",
	"s/S",      "step in / step over",
	"t/T",      "rotate related commands in a panel",
	"x",        "show xrefs/refs of current function from/to data/code",
	"X",        "close current panel",
	"q/Q/Enter","quit zoom mode",
	NULL
};

// clang-format off

// actions listed in the [=] menu of every panel, in display order
static const FrameMenuAction frame_menu_actions[] = {
	{ "Maximize", "Zoom this panel to fill the screen", frame_maximize_cb, frame_maximize_state },
	{ "Cache contents", "Cache the command output of this panel", frame_cache_cb, frame_cache_state },
	{ "--", NULL, NULL, NULL },
	{ "Split Horizontal", "Split this panel in two, one above the other", frame_split_horizontal_cb, NULL },
	{ "Split Vertical", "Split this panel in two, side by side", frame_split_vertical_cb, NULL },
	{ "--", NULL, NULL, NULL },
	{ "Panel contents...", "Replace the contents of this panel", frame_contents_cb, NULL },
	{ "Move to tab", "Move this panel into another tab", frame_move_menu_cb, NULL },
	{ "--", NULL, NULL, NULL },
	{ "Close", "Close this panel", frame_close_cb, NULL },
};

static const ModalEntryDef modal_entries_db[] = {
	{ "Assembly Strings", "/az", NULL, PANEL_CACHE_ON },
	{ "Backtrace", "dbt", NULL },
	{ "Basic Blocks", "afb", NULL },
	{ "Breakpoints", "db", NULL, PANEL_CACHE_OFF },
	{ "Change Command of Current Panel", NULL, replace_current_panel_input },
	{ "Classes", "icq", NULL, PANEL_CACHE_ON },
	{ "Clipboard", "y", NULL },
	{ "Comments", "CC", NULL },
	{ "Console", "cat $console", NULL },
	{ "Create New", NULL, create_panel_input },
	{ "Database", "k ***", NULL },
	{ "Debug Registers", "drx", NULL },
	{ "Decompiler", "pdc", NULL },
	{ "Decompiler With Offsets", "pdco", NULL },
	{ "Disassembly", "pd", NULL },
	{ "Disassembly Summary", "pdsf", NULL },
	{ "Entropy", "p=e 100", NULL },
	{ "Entropy Fire", "p==e 100", NULL },
	{ "Entry Points", "ie", NULL, PANEL_CACHE_ON },
	{ "Enumerations", "te", NULL },
	{ "Exports", "iE", NULL, PANEL_CACHE_ON },
	{ "File Hashes", "it", NULL, PANEL_CACHE_ON },
	{ "Flag Registers (1 bit)", "dr 1", NULL },
	{ "Flag Spaces", "fs", NULL },
	{ "Flags", "f", NULL },
	{ "FPU Registers", "drf", NULL },
	{ "Function Calls", "aflm", NULL },
	{ "Function Disassembly", "pdf", NULL },
	{ "Function Info", "afi", NULL },
	{ "Function Signatures", "tf", NULL },
	{ "Function Variables", "afv", NULL },
	{ "Functions", "afl", NULL },
	{ "Graph", "agf", NULL },
	{ "Headers", "iH", NULL, PANEL_CACHE_ON },
	{ "Hexdump", "xc $r*16", NULL },
	{ "Hexdump References", "pxr $r*16", NULL },
	{ "Imports", "iiq", NULL, PANEL_CACHE_ON },
	{ "Info", "i", NULL },
	{ "IO Maps", "om", NULL },
	{ "Libraries", "il", NULL, PANEL_CACHE_ON },
	{ "Locals", "afvd", NULL },
	{ "Memory Maps", "dm", NULL },
	{ "Methods", "ic", NULL },
	{ "Modules", "dmm", NULL },
	{ "New", "o", NULL },
	{ "Open Files", "o", NULL },
	{ "Processes", "dp", NULL },
	{ "References From", "axf", NULL },
	{ "Register Columns", "dr=", NULL },
	{ "Register References", "drr", NULL },
	{ "Registers", "dr", NULL },
	{ "Relocs", "ir", NULL, PANEL_CACHE_ON },
	{ "Resources", "iu", NULL, PANEL_CACHE_ON },
	{ "Search strings in data sections", NULL, search_strings_data_create },
	{ "Search strings in the whole bin", NULL, search_strings_bin_create },
	{ "Sections", "iSq", NULL },
	{ "Segments", "iSSq", NULL },
	{ "Show All Decompiler Output", NULL, delegate_show_all_decompiler_cb },
	{ "Stack", "pxr@r:SP", NULL },
	{ "Strings in data sections", "izq", NULL },
	{ "Strings in the whole bin", "izzq", NULL },
	{ "Structures", "ts", NULL },
	{ "Symbols", "is,vaddr/cols/size/name,vaddr/sort/inc,vaddr/nostr/--,:quiet", NULL, PANEL_CACHE_ON },
	{ "Syscalls", "/as", NULL, PANEL_CACHE_ON },
	{ "Threads", "dpt", NULL },
	{ "Tiny Graph", "agft", NULL },
	{ "Types", "t", NULL },
	{ "Variable Reads", "afvR", NULL },
	{ "Variable Writes", "afvW", NULL },
	{ "Visual Marks", "fv", NULL },
	{ "XMM Registers", "drv", NULL },
	{ "Xrefs", "ax", NULL },
	{ "Xrefs Here", "ax.", NULL },
	{ "Xrefs To", "axt", NULL },
	{ "YMM Registers", "drvy", NULL }
};

static const char *screen_value_items[] = { "scr.color", NULL };

static const char *manpage_tools[] = {
	"r2agent", "rabin2", "radare2", "rafind2", "ragg2",
	"rahash2", "rarun2", "rasign2", "rasm2", "ravc2", "rax2"
};

static const char *asm_value_items[] = { "asm.var.summary", "asm.arch", "asm.bits", "asm.cpu", NULL };

static const MenuItem file_items[] = {
	{ "New", "Open a new file", NULL },
	{ "Open File", "Prompt for a file and open it", open_file_cb },
	{ "Reopen...", "Reopen the current file with a different mode", open_menu_cb },
	{ "Close File", "Close the current file descriptor", close_file_cb },
	{ "--", NULL, NULL },
	{ "Open Project", "Load a project into the current session", project_open_cb },
	{ "Save Project", "Save the current project state", project_save_cb },
	{ "Close Project", "Close the active project", project_close_cb },
	{ "--", NULL, NULL },
	{ "Quit", "Leave panels mode", quit_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem settings_items[] = {
	{ "Edit radare2rc", "Open the user radare2rc file", r2rc_cb },
	{ "Save Layout", "Save the current panels layout", save_layout_cb },
	{ "Load Layout", "Load a saved or default layout", open_menu_cb },
	{ "Clear Saved Layouts", "Delete every saved panels layout", clear_layout_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem edit_items[] = {
	{ "Copy", "Copy the current selection or line", copy_cb },
	{ "Paste", "Paste the clipboard at the current offset", paste_cb },
	{ "Write String", "Write an ASCII string", write_str_cb },
	{ "Write Hex", "Write raw hexpairs", write_hex_cb },
	{ "Write Value", "Write a numeric value", writeValueCb },
	{ "Assemble", "Assemble and write instructions", assemble_cb },
	{ "Fill", "Fill a block with a repeated value", fill_cb },
	{ "io.cache", "Toggle io.cache helpers", open_menu_cb },
	{ "Settings", "Configuration, themes and layouts", open_menu_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem view_items[] = {
	{ "Show All Decompiler Output", "Expand the full decompiler output", show_all_decompiler_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem tools_items[] = {
	{ "Calculator", "Open the expression calculator", calculator_cb },
	{ "Assembler", "Open the assembler helper", r2_assembler_cb },
	{ "R2 Shell", "Run commands inside an r2 shell", shell_r2_cb },
	{ "System Shell", "Open a system shell", shell_system_cb },
	{ "FSMount Shell", "Browse mounted filesystems", shell_fs_cb },
	{ "R2JS Shell", "Open an R2JS shell", shell_r2js_cb },
	{ "File Manager", "Open the file manager", shell_mmc_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem search_items[] = {
	{ "String (Whole Bin)", "Search strings in the whole binary", string_whole_bin_cb },
	{ "String (Data Sections)", "Search strings in data sections only", string_data_sec_cb },
	{ "Assembly Strings", "Search assembly constructed strings (/az)", add_cmd_panel },
	{ "Syscalls", "Search syscall instructions (/as)", add_cmd_panel },
	{ "ROP", "Search for gadgets", rop_cb },
	{ "Magic", "Run magic signatures", magic_cb },
	{ "Code", "Search for code sequences", code_cb },
	{ "Hexpairs", "Search for raw hexpairs", hexpairs_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem emulate_items[] = {
	{ "Step From", "Emulate from the current address", esil_init_cb },
	{ "Step To", "Emulate until a target address", esil_step_to_cb },
	{ "Step Range", "Emulate a range of addresses", esil_step_range_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem debug_items[] = {
	{ "Toggle Breakpoint", "Toggle a breakpoint at an address", break_points_cb },
	{ "Add Watchpoint", "Set a watchpoint at an address", watch_points_cb },
	{ "Continue", "Resume execution", continue_cb },
	{ "Step", "Single-step into the next instruction", step_cb },
	{ "Step Over", "Single-step over the next instruction", step_over_cb },
	{ "Reload", "Reload the current debugging session", reload_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem analyze_items[] = {
	{ "Function", "Analyze the current function", function_cb },
	{ "Symbols", "Analyze symbols into functions and metadata", symbols_cb },
	{ "Program", "Run broad program analysis", program_cb },
	{ "BasicBlocks", "Analyze basic blocks", basic_blocks_cb },
	{ "Preludes", "Find function preludes", aap_cb },
	{ "Emulation", "Analyze through emulation", aae_cb },
	{ "Calls", "Analyze calls and callees", calls_cb },
	{ "References", "Analyze references", references_cb },
	{ "Plugins...", "Browse analysis plugin commands", open_menu_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem help_items[] = {
	{ "License", "Show the software license", license_cb },
	{ "Version", "Show the short version", version_cb },
	{ "Full Version", "Show the full version report", version2_cb },
	{ "Fortune", "Print a random fortune", fortune_cb },
	{ "2048", "Open the 2048 game", game_cb },
	{ "Manpages...", "Browse bundled manpages", open_menu_cb },
	{ "Toggle Help", "Toggle the panels help view", help_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem reopen_items[] = {
	{ "In Read+Write", "Reopen the file in read-write mode", rw_cb },
	{ "In Debugger", "Reopen the file in debugger mode", debugger_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem loadlayout_items[] = {
	{ "Saved..", "Choose one of the saved layouts", open_menu_cb },
	{ "Default", "Restore the default layout", load_layout_default_cb },
	{ NULL, NULL, NULL }
};

static const MenuItem iocache_items[] = {
	{ "On", "Enable io.cache", io_cache_on_cb },
	{ "Off", "Disable io.cache", io_cache_off_cb },
	{ NULL, NULL, NULL }
};

