/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_sign.h>
#include <r_anal.h>

R_LIB_VERSION (r_sign);

R_API RSign *r_sign_new() {
	RSign *sig = R_NEW0 (RSign);
	if (sig) {
		sig->s_byte = sig->s_anal = 0;
		sig->ns[0] = '\0';
		sig->printf = (PrintfCallback) printf;
		sig->items = r_list_new ();
		sig->items->free = r_sign_item_free;
	}
	return sig;
}

R_API void r_sign_ns(RSign *sig, const char *str) {
    /*Set namespace*/
	if (str) {
		strncpy (sig->ns, str, sizeof (sig->ns)-1);
		sig->ns[sizeof (sig->ns)-1] = '\0';
	} else sig->ns[0] = '\0';
}

R_API int r_sign_add(RSign *sig, RAnal *anal, int type, const char *name, const char *arg) {
	int len, ret = R_FALSE;
	char *data = NULL, *ptr;
	RSignItem *si; // TODO: like in r_search.. we need r_sign_item_new ()
			// TODO: but..we need to use a pool here..
	if (!name || !arg || !anal)
		return R_FALSE;

	if (!(si = R_NEW0 (RSignItem)))
		return R_FALSE;
	si->type = type;
	snprintf (si->name, sizeof (si->name), "%s.%c.%s",
		*sig->ns? sig->ns: "sign", type, name);

	switch (type) {
	case R_SIGN_FUNC: // function signature
		// FUNC FORMAT [addr] [function-signature]
		ptr = strchr (arg, ' ');
		if (ptr) {
		// TODO. matching must be done by sym/flag/function name
		//	sig->addr =
		}
		sig->s_func++;
		r_list_append (sig->items, si);
		break;
	case R_SIGN_HEAD: // function prefix (push ebp..)
	case R_SIGN_BYTE: // function mask
		if (!(data = r_anal_strmask (anal, arg))) {
			r_sign_item_free (si);
			break;
		}
		len = strlen (data)+4; // \xf0
		si->bytes = (ut8 *)malloc (R_MAX (len, 4));
		si->mask = (ut8 *)malloc (R_MAX (len, 4));
		if (si->bytes == NULL || si->mask == NULL) {
			eprintf ("Cannot malloc\n");
			r_sign_item_free (si);
			break;
		}
		si->size = r_hex_str2binmask (data, si->bytes, si->mask);
		if (si->size<1) {
			r_sign_item_free (si);
		} else {
			r_list_append (sig->items, si);
			if (type==R_SIGN_HEAD)
				sig->s_head++;
			else if (type==R_SIGN_BYTE)
				sig->s_byte++;
		}
		break;
	default:
	case R_SIGN_ANAL:
		eprintf ("r_sign_add: TODO. unsupported signature type %d\n", type);
		r_sign_item_free (si);
		break;
	}
	free (data);
	return ret;
}

R_API void r_sign_list(RSign *sig, int rad) {
	if (rad) {
		int i;
		RListIter *iter;
		RSignItem *si;
		if (!r_list_empty (sig->items))
			sig->printf ("zp-\n");
		r_list_foreach (sig->items, iter, si) {
			sig->printf ("z%c %s ", si->type, si->name);
			for (i=0; i<si->size; i++){
				if (!si->mask[i]) // This is a mask
					sig->printf ("..");
				else
					sig->printf ("%02x", si->bytes[i]);
			}
			sig->printf ("\n");
		}
	} else {
		sig->printf ("Loaded %d signatures\n", sig->s_byte + sig->s_anal + sig->s_func);
		sig->printf ("  %d byte signatures\n", sig->s_byte);
		sig->printf ("  %d head signatures\n", sig->s_head);
		sig->printf ("  %d func signatures\n", sig->s_func);
	}
}

R_API void r_sign_reset(RSign *sig) {
	if (!sig)
		return;
	r_list_free (sig->items);
	sig->items = r_list_new ();
	sig->s_anal = sig->s_byte = sig->s_head = sig->s_func = 0;
}

R_API int r_sign_remove_ns(RSign* sig, const char* ns) {
    /*Remove namespace*/
	RListIter* iter, *iter2;
	RSignItem* si;
	int plen, i = 0;

	if (!sig || !ns)
		return -1;

	plen = strlen (ns);
	r_list_foreach_safe (sig->items, iter, iter2, si) {
		if (!strncmp (si->name, ns, plen)) {
			if (si->type == R_SIGN_BYTE)
				sig->s_byte--;
			else if (si->type == R_SIGN_ANAL)
				sig->s_anal--;
			else if (si->type == R_SIGN_HEAD)
				sig->s_head--;
			r_list_delete (sig->items, iter);
			i++;
		}
	}
	return i;
}

R_API RSign *r_sign_free(RSign *sig) {
	if (!sig) return NULL;
	r_list_free (sig->items);
	free (sig);
	return NULL;
}

R_API void r_sign_item_free(void *_item) {
	if (_item) {
		RSignItem *item = _item;
		free (item->bytes);
		free (item->mask);
		free (item);
	}
}


R_API RSignItem *r_sign_check(RSign *sig, const ut8 *buf, int len) {
	RListIter *iter;
	RSignItem *si;

	if (!sig || !buf)
		return NULL;

	r_list_foreach (sig->items, iter, si) {
		if (si->type == R_SIGN_BYTE) {
			int l = (len>si->size)?si->size:len;
			if (!r_mem_cmp_mask (buf, si->bytes, si->mask, l))
				return si;
		}
	}
	return NULL;
}
