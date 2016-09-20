/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <r_sign.h>
#include <r_anal.h>

R_LIB_VERSION (r_sign);

R_API RSign *r_sign_new() {
	RSign *sig = R_NEW0 (RSign);
	if (sig) {
		sig->cb_printf = (PrintfCallback) printf;
		sig->items = r_list_new ();
		if (!sig->items) {
			free (sig);
			return NULL;
		}
		sig->items->free = r_sign_item_free;
	}
	return sig;
}

R_API void r_sign_ns(RSign *sig, const char *str) {
	/*Set namespace*/
	if (str) {
		free (sig->ns);
		sig->ns = strdup (str);
	} else {
		sig->ns = NULL;
	}
}

R_API bool r_sign_add(RSign *sig, RAnal *anal, int type, const char *name, const char *arg) {
	int len;
	char *data = NULL, *ptr;
	RSignItem *si; // TODO: like in r_search.. we need r_sign_item_new ()
			// TODO: but..we need to use a pool here..
	if (!name || !arg || !anal) {
		return false;
	}
	if (!(si = R_NEW0 (RSignItem))) {
		return false;
	}
	si->type = type;
	si->name = r_str_newf ("%s.%c.%s", sig->ns? sig->ns: "sys", type, name);

	switch (type) {
	case R_SIGN_FUNC: // function signature
		// FUNC FORMAT [addr] [function-signature]
		ptr = strchr (arg, ' ');
		if (ptr) {
		// TODO. matching must be done by sym/flag/function name
		//	sig->addr =
		}
		sig->s_func++;
		if (!r_list_append (sig->items, si)) {
			r_sign_item_free (si);
		}
		break;
	case R_SIGN_HEAD: // function prefix (push ebp..)
	case R_SIGN_BYTE: // function mask
	case R_SIGN_BODY: // function body
		if (!(data = r_anal_strmask (anal, arg))) {
			r_sign_item_free (si);
			break;
		}
		len = strlen (data)+4; // \xf0
		si->bytes = (ut8 *)malloc (R_MAX (len, 4));
		si->mask = (ut8 *)malloc (R_MAX (len, 4));
		if (!si->bytes || !si->mask) {
			eprintf ("Cannot malloc\n");
			r_sign_item_free (si);
			break;
		}
		si->size = r_hex_str2binmask (data, si->bytes, si->mask);
		if (si->size<1) {
			r_sign_item_free (si);
		} else {
			r_list_append (sig->items, si);
			if (type == R_SIGN_HEAD)
				sig->s_head++;
			else if (type == R_SIGN_BYTE)
				sig->s_byte++;
			else if(type == R_SIGN_BODY)
				sig->s_func++;
		}
		break;
	default:
	case R_SIGN_ANAL:
		eprintf ("r_sign_add: TODO. unsupported signature type %d\n", type);
		r_sign_item_free (si);
		break;
	}
	free (data);
	return false;
}

R_API void r_sign_list(RSign *sig, int rad, int json) {
	if (rad) {
		int i;
		RListIter *iter;
		RSignItem *si;
		if (!r_list_empty (sig->items))
			sig->cb_printf ("zp-\n");
		r_list_foreach (sig->items, iter, si) {
			sig->cb_printf ("z%c %s ", si->type, si->name);
			for (i=0; i<si->size; i++){
				if (!si->mask[i]) // This is a mask
					sig->cb_printf ("..");
				else
					sig->cb_printf ("%02x", si->bytes[i]);
			}
			sig->cb_printf ("\n");
		}
	} else {
		if (json) {
			sig->cb_printf("{\"byte_signatures\":\"%d\","
					"\"head_signatures\":\"%d\","
					"\"func_signatures\":\"%d\","
					"\"matches\":\"%d\"}\n", sig->s_byte, sig->s_head,
					sig->s_func,sig->matches);
		} else {
			const int total = sig->s_byte + sig->s_anal + sig->s_func;
			sig->cb_printf ("Loaded %d signatures\n", total);
			sig->cb_printf ("  %d byte signatures\n", sig->s_byte);
			sig->cb_printf ("  %d head signatures\n", sig->s_head);
			sig->cb_printf ("  %d func signatures\n", sig->s_func);
			sig->cb_printf ("Found %d matches\n", sig->matches);
		}
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

	if (!sig || !ns) {
		return -1;
	}
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
	if (sig) {
		r_list_free (sig->items);
		free (sig->ns);
		free (sig);
	}
	return NULL;
}

R_API void r_sign_item_free(void *_item) {
	if (_item) {
		RSignItem *item = _item;
		free (item->bytes);
		free (item->mask);
		free (item->name);
		free (item);
	}
}

R_API RSignItem *r_sign_check(RSign *sig, const ut8 *buf, int len) {
	RListIter *iter;
	RSignItem *si;

	if (!sig || !buf) {
		return NULL;
	}
	r_list_foreach (sig->items, iter, si) {
		if ((si->type == R_SIGN_BYTE) || (si->type == R_SIGN_BODY)) {
			int l = (len>si->size)?si->size:len;
			if (!r_mem_cmp_mask (buf, si->bytes, si->mask, l))
				return si;
		}
	}
	return NULL;
}
