/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_sign.h>
#include <r_anal.h>

R_API RSign *r_sign_new() {
	RSign *sig = R_NEW (RSign);
	if (sig) {
		sig->s_byte = sig->s_anal = 0;
		sig->prefix[0] = '\0';
		sig->printf = (PrintfCallback) printf;
		sig->items = r_list_new ();
		sig->items->free = r_sign_item_free;
	}
	return sig;
}

R_API void r_sign_prefix(RSign *sig, const char *str) {
	strncpy (sig->prefix, str, sizeof (sig->prefix)-1);
	sig->prefix[sizeof (sig->prefix)-1] = '\0';
}

R_API int r_sign_add(RSign *sig, RAnal *anal, int type, const char *name, const char *arg) {
	int len, ret = R_FALSE;
	char *data, *ptr;
	RSignItem *si; // TODO: like in r_search.. we need r_sign_item_new ()
			// TODO: but..we need to use a pool here..
	if (!name || !arg || !anal)
		return R_FALSE;

	if (!(si = R_NEW (RSignItem)))
		return R_FALSE;
	si->type = type;
	snprintf (si->name, sizeof (si->name), "%s.%c.%s",
		*sig->prefix?sig->prefix:"sign", type, name);

	switch (type) {
	case R_SIGN_FUNC: // function signature
		sig->s_func++;
		// FUNC FORMAT [addr] [function-signature]
		ptr = strchr (arg, ' ');
		if (ptr) {
		// TODO. matching must be done by sym/flag/function name
		//	sig->addr = 
		}
		r_list_append (sig->items, si);
		break;
	case R_SIGN_HEAD: // function prefix (push ebp..)
	case R_SIGN_BYTE: // function mask
		if (type==R_SIGN_HEAD)
		sig->s_head++;
		else if (type==R_SIGN_BYTE)
			sig->s_byte++;
		if (!(data = r_anal_strmask (anal, arg))) {
			free (si);
			break;
		}
		len = strlen (data)+1;
		si->bytes = (ut8 *)malloc (len);
		si->mask = (ut8 *)malloc (len);
		if (si->bytes == NULL || si->mask == NULL) {
			eprintf ("Cannot malloc\n");
			free (si->mask);
			free (si->bytes);
			free (si);
			break;
		}
		si->size = r_hex_str2binmask (data, si->bytes, si->mask);
		if (si->size<1) {
			free (si->bytes);
			free (si->mask);
			free (si);
		} else r_list_append (sig->items, si);
		free (data);
		break;
	default:
	case R_SIGN_ANAL:
		eprintf ("r_sign_add: TODO. unsupported signature type %d\n", type);
		break;
	}
	return ret;
}

R_API void r_sign_list(RSign *sig, int rad) {
	if (rad) {
		RListIter *iter;
		RSignItem *si;
		sig->printf ("zp-");
		r_list_foreach (sig->items, iter, si)
			sig->printf ("z%c %s ...\n", si->type, si->name); // TODO : show bytes
	} else {
		sig->printf ("Loaded %d signatures\n", sig->s_byte + sig->s_anal);
		sig->printf ("  %d byte signatures\n", sig->s_byte);
		sig->printf ("  %d head signatures\n", sig->s_head);
		sig->printf ("  %d func signatures\n", sig->s_func);
	}
}

R_API void r_sign_reset(RSign *sig) {
	r_list_free (sig->items);
	sig->items = r_list_new ();
}

R_API RSign *r_sign_free(RSign *sig) {
	r_list_free (sig->items);
	free (sig);
	return NULL;
}

R_API void r_sign_item_free(void *_item) {
	RSignItem *item = _item;
	free (item->bytes);
	free (item->mask);
	free (item);
}


R_API RSignItem *r_sign_check(RSign *sig, const ut8 *buf, int len) {
	RListIter *iter;
	RSignItem *si;
	r_list_foreach (sig->items, iter, si) {
		if (si->type == R_SIGN_BYTE) {
			int l = (len>si->size)?si->size:len;
			if (!r_mem_cmp_mask (buf, si->bytes, si->mask, l))
				return si;
		}
	}
	return NULL;
}
