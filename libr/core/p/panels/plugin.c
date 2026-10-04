/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

#include <r_core_priv.h>
#include "panels.h"
#include "../../visual_modes.h"

#include "data.inc.c"
#include "model.inc.c"
#include "layout.inc.c"
#include "render.inc.c"
#include "menus.inc.c"
#include "actions.inc.c"
#include "input.inc.c"
#include "mouse.inc.c"
#include "tabs.inc.c"
#include "modal.inc.c"
#include "views.inc.c"
#include "config.inc.c"
#include "session.inc.c"

static RCoreHelpMessage help_msg_v = {
	"Usage:", "v[*i]", "",
	"v", "", "open visual panels",
	"v", " test", "load saved layout with name test",
	"ve", " [fg] [bg]", "define foreground and background for current panel",
	"v.", " [file]", "load visual script (also known as slides)",
	"v=", " test", "save current layout with name test",
	"vi", " test", "open the file test in 'cfg.editor'",
	NULL
};

static int panels_command(RCore *core, const char *input) {
	if (core->vmode) {
		return false;
	}
	if (*input == '.') {
		const char *f = r_str_trim_head_ro (input + 1);
		if (*f) {
			r_core_visual_slides (core, f);
		}
		return false;
	}
	if (*input == '?') {
		r_cons_cmd_help (core->cons, help_msg_v);
		return false;
	}
	if (!r_cons_is_interactive (core->cons)) {
		R_LOG_ERROR ("Panel mode requires scr.interactive=true");
		return false;
	}
	if (*input == ' ') {
		if (core->panels) {
			r_core_panels_load (core, input + 1);
		}
		r_config_set (core->config, "scr.layout", input + 1);
		return true;
	}
	if (*input == 'e') {
		if (input[1] == ' ') {
			RPanel *pan = core->panels? r_panels_get_cur_panel (core->panels): NULL;
			if (pan) {
				char *r = r_cons_pal_parse (core->cons, r_str_trim_head_ro (input + 2), NULL);
				if (r) {
					free (pan->model->bgcolor);
					pan->model->bgcolor = r_str_newf (Color_RESET"%s", r);
					free (r);
				} else {
					R_LOG_ERROR ("Invalid color %sXXX"Color_RESET, r);
				}
			}
		} else {
			r_cons_cmd_help_match (core->cons, help_msg_v, "ve", 0, true);
		}
		return true;
	}
	if (*input == '=') {
		if (input[1]) {
			r_core_panels_save (core, input + 1);
			r_config_set (core->config, "scr.layout", input + 1);
		} else {
			r_cons_cmd_help_match (core->cons, help_msg_v, "v=", 0, true);
		}
		return true;
	}
	if (*input == 'i') {
		char *sp = strchr (input, ' ');
		if (sp) {
			char *r = r_core_editor (core, sp + 1, NULL, NULL);
			if (r) {
				free (r);
			} else {
				R_LOG_ERROR ("Cannot open file (%s)", sp + 1);
			}
		} else {
			r_cons_cmd_help_match (core->cons, help_msg_v, "vi", 0, true);
		}
		return false;
	}
	if (*input) {
		r_cons_cmd_help (core->cons, help_msg_v);
	} else {
		r_core_panels_root (core, core->panels_root);
	}
	return true;
}

static RCmdResult panels_callback(RCmdContext *ctx) {
	return (RCmdResult) { .status = panels_command (ctx->user, ctx->subcmd.a) };
}

static const RCorePanels panels_api = {
	.root = panels_root,
	.save = panels_save,
	.load = panels_load,
};

static bool panels_plugin_init(RCorePluginSession *session) {
	RCorePriv *priv = session->core->priv;
	if (priv->panels) {
		return false;
	}
	priv->panels = &panels_api;
	return true;
}

static bool panels_plugin_fini(RCorePluginSession *session) {
	RCore *core = session->core;
	RCorePriv *priv = core->priv;
	priv->panels = NULL;
	r_panels_root_free (core->panels_root);
	core->panels_root = NULL;
	core->panels = NULL;
	return true;
}

RCorePlugin r_core_plugin_panels = {
	.meta = {
		.name = "panels",
		.desc = "Visual panels interface",
		.license = "LGPL-3.0-only",
		.author = "pancake, vane11ope",
	},
	.init = panels_plugin_init,
	.fini = panels_plugin_fini,
	.command = "v",
	.call_ctx = panels_callback,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_panels,
	.version = R2_VERSION
};
#endif
