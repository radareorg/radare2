/* radare2 - LGPL - Copyright 2022 - condret */

#include <r_arch.h>
#include <r_util.h>

R_API bool r_arch_load_decoder(RArch *arch, const char *dname) {
	r_return_val_if_fail (dname && arch && arch->plugins && arch->decoders, false);
	RArchDecoder *decoder = (RArchDecoder *)ht_pp_find (arch->decoders, dname, NULL);
	if (decoder) {
		decoder->refctr++;
		return true;
	}
	decoder = R_NEW (RArchDecoder);
	if (!decoder) {
		return false;
	}
	RListIter *iter;
	r_list_foreach (arch->plugins, iter, decoder->p) {
		if (!strcmp (decoder->p->name, dname)) {
			// plugins with init also MUST have fini
			if (decoder->p->init && decoder->p->fini) {
				if (!decoder->p->init (&decoder->user)) {
					free (decoder);
					return false;
				}
			} else {
				decoder->user = NULL;
			}
			if (ht_pp_insert (arch->decoders, dname, decoder)) {
				decoder->refctr = 1;
				if (!arch->current) {
					arch->current = decoder;
				}
				return true;
			}
			if (decoder->p->fini) {
				decoder->p->fini (decoder->user);
			}
			free (decoder);
			return false;
		}
	}
	free (decoder);
	return false;
}

R_API bool r_arch_use_decoder(RArch *arch, const char *dname) {
	r_return_val_if_fail (dname && arch && arch->decoders, false);
	if (!arch->current) {
		return r_arch_load_decoder (arch, dname);
	}
	if (!strcmp (arch->current->p->name, dname)) {
		return true;
	}
	RArchDecoder *decoder = (RArchDecoder *)ht_pp_find (arch->decoders, dname, NULL);
	if (!decoder) {
		decoder = arch->current;
		arch->current = NULL;
		if (!r_arch_load_decoder (arch, dname)) {
			arch->current = decoder;
			return false;
		}
		return true;
	}
	arch->current = decoder;
	return true;
}

static bool _pick_any_decoder_as_current (void *user, const char *dname, const void *dec) {
	RArch *arch = (RArch *)user;
	arch->current = (RArchDecoder *)dec;
	return false;
}

R_API bool r_arch_unload_decoder(RArch *arch, const char *dname) {
	r_return_val_if_fail (arch && arch->decoders, false);
	RArchDecoder *decoder = NULL;
	if (dname) {
		decoder = (RArchDecoder *)ht_pp_find (arch->decoders, dname, NULL);
	} else {
		decoder = arch->current;
	}
	if (!decoder) {
		return false;
	}
	decoder->refctr--;
	if (decoder->refctr) {
		return true;
	}
	ht_pp_delete (arch->decoders, decoder->p->name);
	if (arch->current == decoder) {
		arch->current = NULL;
		ht_pp_foreach (arch->decoders, (HtPPForeachCallback)_pick_any_decoder_as_current, arch);
	}
	return true;
}

R_API int r_arch_info(RArch *arch, const char *dname, ut32 query) {
	r_return_val_if_fail (arch && arch->decoders, -1);
	RArchDecoder *decoder = NULL;
	if (dname) {
		decoder = (RArchDecoder *)ht_pp_find (arch->decoders, dname, NULL);
	} else {
		decoder = arch->current;
	}
	if (!decoder || !decoder->p->info) {
		return -1;
	}
	return decoder->p->info (arch->cfg, query);
}

R_API int r_arch_decode(RArch *arch, const char *dname, RArchOp *op, ut64 addr, const ut8 *data, int len, ut32 mask) {
	r_return_val_if_fail (arch && op && data && (len > 0), -1);
	RArchDecoder *decoder = NULL;
	if (dname) {
		decoder = (RArchDecoder *)ht_pp_find (arch->decoders, dname, NULL);
	} else {
		decoder = arch->current;
	}
	if (!decoder || !decoder->p->decode) {
		return -1;
	}
	return decoder->p->decode (decoder->user, arch->cfg, op, addr, data, len, mask);
}
