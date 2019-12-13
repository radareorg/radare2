/* radare - LGPL - Copyright 2006-2019 - pancake */

#include <r_config.h>

static void r_config_hold_char_free(RConfigHoldChar *hc) {
	free (hc->value);
	free (hc);
}

static void r_config_hold_num_free(RConfigHoldNum *hc) {
	free (hc);
}

R_API bool r_config_hold_s(RConfigHold *h, ...) {
	va_list ap;
	char *key;
	va_start (ap, h);
	if (!h->list_char) {
		h->list_char = r_list_newf ((RListFree)r_config_hold_char_free);
		if (!h->list_char) {
			va_end (ap);
			return false;
		}
	}
	while ((key = va_arg (ap, char *))) {
		RConfigHoldChar *hc = R_NEW0 (RConfigHoldChar);
		if (hc) {
			hc->key = key;
			hc->value = strdup (r_config_get (h->cfg, key));
			r_list_append (h->list_char, hc);
		}
	}
	va_end (ap);
	return true;
}

R_API bool r_config_hold_i(RConfigHold *h, ...) {
	va_list ap;
	char *key;
	if (!h) {
		return false;
	}
	if (!h->list_num) {
		h->list_num = r_list_newf ((RListFree)r_config_hold_num_free);
		if (!h->list_num) {
			return false;
		}
	}
	va_start (ap, h);
	while ((key = va_arg (ap, char *))) {
		RConfigHoldNum *hc = R_NEW0 (RConfigHoldNum);
		if (!hc) {
			continue;
		}
		hc->key = key;
		hc->value = r_config_get_i (h->cfg, key);
		r_list_append (h->list_num, hc);
	}
	va_end (ap);
	return true;
}

R_API RConfigHold* r_config_hold_new(RConfig *cfg) {
	if (cfg) {
		RConfigHold *hold = R_NEW0 (RConfigHold);
		if (hold) {
			hold->cfg = cfg;
			return hold;
		}
	}
	return NULL;
}

R_API void r_config_hold_restore(RConfigHold *h) {
	RListIter *iter;
	RConfigHoldChar *hchar;
	RConfigHoldNum *hnum;
	if (h) {
		RConfig *cfg = h->cfg;
		r_list_foreach (h->list_num, iter, hnum) {
			(void)r_config_set_i (cfg, hnum->key, hnum->value);
		}
		r_list_foreach (h->list_char, iter, hchar) {
			(void)r_config_set (cfg, hchar->key, hchar->value);
		}
	}
}

R_API void r_config_hold_free(RConfigHold *h) {
	if (h) {
		r_list_free (h->list_num);
		r_list_free (h->list_char);
		R_FREE (h);
	}
}
