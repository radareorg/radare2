/* radare2 - LGPL - Copyright 2014-2026 - pancake, vane11ope */

#include <r_core_priv.h>

#include "p/panels/free.h"

R_API void r_panels_root_free(RPanelsRoot *panels_root) {
	if (!panels_root) {
		return;
	}
	if (panels_root->panels) {
		int i;
		for (i = 0; i < panels_root->n_panels; i++) {
			r_panels_free_partial (panels_root->panels[i]);
		}
		free (panels_root->panels);
	}
	sdb_free (panels_root->pdc_caches);
	free (panels_root);
}

R_API bool r_core_panels_root(RCore *core, RPanelsRoot *panels_root) {
	R_RETURN_VAL_IF_FAIL (core, false);
	RCorePriv *priv = core->priv;
	if (!priv->panels) {
		R_LOG_ERROR ("The panels core plugin is not loaded");
		return false;
	}
	return priv->panels->root (core, panels_root);
}

R_API void r_core_panels_save(RCore *core, const char *name) {
	R_RETURN_IF_FAIL (core);
	RCorePriv *priv = core->priv;
	if (priv->panels) {
		priv->panels->save (core, name);
	}
}

R_API bool r_core_panels_load(RCore *core, const char *name) {
	R_RETURN_VAL_IF_FAIL (core, false);
	RCorePriv *priv = core->priv;
	return priv->panels && priv->panels->load (core, name);
}
