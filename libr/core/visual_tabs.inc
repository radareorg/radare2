
static void r_core_visual_tab_free (RCoreVisualTab *tab) {
	free (tab);
}

static int __core_visual_tab_count (RCore *core) {
	return core->visual.tabs? r_list_length (core->visual.tabs): 0;
}

static char *__core_visual_tab_string(RCore *core, const char *kolor) {
	int hex_cols = r_config_get_i (core->config, "hex.cols");
	int scr_color = r_config_get_i (core->config, "scr.color");
	if (hex_cols < 4) {
		return strdup ("");
	}
	int i = 0;
	char *str = NULL;
	int tabs = r_list_length (core->visual.tabs);
	if (scr_color > 0) {
		// TODO: use theme
		if (tabs > 0) {
			str = r_str_appendf (str, "%s-+__", kolor);
		}
		for (i = 0; i < tabs;i++) {
			RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, i);
			const char *name = (tab && *tab->name)? tab->name: NULL;
			if (i == core->visual.tab) {
				str = r_str_appendf (str, Color_WHITE"_/ %s \\_%s", r_str_get_fail (name, "t="), kolor);
			} else {
				str = r_str_appendf (str, "_%s(%d)_", r_str_get (name), i + 1);
			}
		}
	} else {
		if (tabs > 0) {
			str = r_str_append (str, "___");
		}
		for (i = 0;i < tabs; i++) {
			const char *name = NULL;
			RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, i);
			if (tab && *tab->name) {
				name = tab->name;
			}
			if (i==core->visual.tab) {
				str = r_str_appendf (str, "_/ %d:%s \\_", i + 1, r_str_get_fail (name, "'="));
			} else {
				str = r_str_appendf (str, "_(t%d%s%s)__", i + 1, name ? ":" : "", r_str_get (name));
			}
		}
	}
	if (str) {
		int n = 79 - r_str_ansi_len (str);
		if (n > 0) {
			str = r_str_append (str, r_str_pad ('_', n));
		}
		str = r_str_append (str, "\n"Color_RESET);
	}
	return str;
}

static void visual_tabset(RCore *core, RCoreVisualTab *tab) {
	r_return_if_fail (core && tab);

	r_core_seek (core, tab->offset, true);
	core->printidx = tab->printidx;
	core->print->cur_enabled = tab->cur_enabled;
	core->print->cur = tab->cur;
	core->print->ocur = tab->ocur;
	disMode = tab->disMode;
	hexMode = tab->hexMode;
	printMode = tab->printMode;
	current3format = tab->current3format;
	current4format = tab->current4format;
	current5format = tab->current5format;
	r_core_visual_applyDisMode (core, disMode);
	r_core_visual_applyHexMode (core, hexMode);
	r_config_set_i (core->config, "asm.offset", tab->asm_offset);
	r_config_set_i (core->config, "asm.instr", tab->asm_instr);
	r_config_set_i (core->config, "asm.bytes", tab->asm_bytes);
	r_config_set_i (core->config, "asm.indent", tab->asm_indent);
	r_config_set_i (core->config, "asm.cmt.col", tab->asm_cmt_col);
	r_config_set_i (core->config, "hex.cols", tab->cols);
	r_config_set_i (core->config, "scr.dumpcols", tab->dumpCols);
	printfmtSingle[0] = printHexFormats[R_ABS(hexMode) % PRINT_HEX_FORMATS];
	printfmtSingle[2] = print3Formats[R_ABS(current3format) % PRINT_3_FORMATS];
	printfmtSingle[3] = print4Formats[R_ABS(current4format) % PRINT_4_FORMATS];
	printfmtSingle[4] = print5Formats[R_ABS(current5format) % PRINT_5_FORMATS];
}

static void visual_tabget(RCore *core, RCoreVisualTab *tab) {
	r_return_if_fail (core && tab);

	tab->offset = core->offset;
	tab->printidx = core->printidx;
	tab->asm_offset = r_config_get_i (core->config, "asm.offset");
	tab->asm_instr = r_config_get_i (core->config, "asm.instr");
	tab->asm_indent = r_config_get_i (core->config, "asm.indent");
	tab->asm_bytes = r_config_get_i (core->config, "asm.bytes");
	tab->asm_cmt_col = r_config_get_i (core->config, "asm.cmt.col");
	tab->cur_enabled = core->print->cur_enabled;
	tab->cur = core->print->cur;
	tab->ocur = core->print->ocur;
	tab->cols = r_config_get_i (core->config, "hex.cols");
	tab->dumpCols = r_config_get_i (core->config, "scr.dumpcols");
	tab->disMode = disMode;
	tab->hexMode = hexMode;
	tab->printMode = printMode;
	tab->current3format = current3format;
	tab->current4format = current4format;
	tab->current5format = current5format;
	// tab->cols = core->print->cols;
}

static RCoreVisualTab *r_core_visual_tab_new(RCore *core) {
	RCoreVisualTab *tab = R_NEW0 (RCoreVisualTab);
	if (tab) {
		visual_tabget (core, tab);
	}
	return tab;
}

static void r_core_visual_tab_update(RCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
	if (tab) {
		visual_tabget (core, tab);
	}
}

static RCoreVisualTab *visual_newtab (RCore *core) {
	if (!core->visual.tabs) {
		core->visual.tabs = r_list_newf ((RListFree)r_core_visual_tab_free);
		if (!core->visual.tabs) {
			return NULL;
		}
		core->visual.tab = -1;
		visual_newtab (core);
	}
	core->visual.tab++;
	RCoreVisualTab *tab = r_core_visual_tab_new (core);
	if (tab) {
		r_list_append (core->visual.tabs, tab);
		visual_tabset (core, tab);
	}
	return tab;
}

static void visual_nthtab (RCore *core, int n) {
	if (!core->visual.tabs || n < 0 || n >= r_list_length (core->visual.tabs)) {
		return;
	}
	core->visual.tab = n;
	RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
	if (tab) {
		visual_tabset (core, tab);
	}
}

static void visual_tabname (RCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	char name[32]={0};
	prompt_read ("tab name: ", name, sizeof (name));
	RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
	if (tab) {
		strcpy (tab->name, name);
	}
}

static void visual_nexttab (RCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	if (core->visual.tab >= r_list_length (core->visual.tabs) - 1) {
		core->visual.tab = -1;
	}
	core->visual.tab++;
	RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
	if (tab) {
		visual_tabset (core, tab);
	}
}

static void visual_prevtab (RCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	if (core->visual.tab < 1) {
		core->visual.tab = r_list_length (core->visual.tabs) - 1;
	} else {
		core->visual.tab--;
	}
	RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
	if (tab) {
		visual_tabset (core, tab);
	}
}

static void visual_closetab (RCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
	if (tab) {
		r_list_delete_data (core->visual.tabs, tab);
		const int tabsCount = r_list_length (core->visual.tabs);
		if (tabsCount > 0) {
			if (core->visual.tab > 0) {
				core->visual.tab--;
			}
			RCoreVisualTab *tab = r_list_get_n (core->visual.tabs, core->visual.tab);
			if (tab) {
				visual_tabset(core, tab);
			}
		} else {
			r_list_free (core->visual.tabs);
			core->visual.tabs = NULL;
		}
	}
}
