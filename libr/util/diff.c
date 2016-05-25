/* radare - LGPL - Copyright 2009-2016 - pancake, nikolai */

#include <r_diff.h>

//R_LIB_VERSION (r_diff);

R_API RDiff *r_diff_new_from(ut64 off_a, ut64 off_b) {
	RDiff *d = R_NEW0 (RDiff);
	if (d) {
		d->delta = 1;
		d->user = NULL;
		d->off_a = off_a;
		d->off_b = off_b;
	}
	return d;
}

R_API RDiff *r_diff_new() {
	return r_diff_new_from (0, 0);
}

R_API RDiff *r_diff_free(RDiff *d) {
	free (d);
	return NULL;
}

R_API int r_diff_set_callback(RDiff *d, RDiffCallback callback, void *user) {
	d->callback = callback;
	d->user = user;
	return 1;
}

R_API int r_diff_set_delta(RDiff *d, int delta) {
	d->delta = delta;
	return 1;
}

R_API int r_diff_buffers_static(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb) {
	int i, len;
	int hit = 0;
	la = R_ABS(la);
	lb = R_ABS(lb);
	if (la != lb) {
	 	len = R_MIN(la, lb);
		fprintf(stderr,
			"Buffer truncated to %d bytes (%d not compared)\n",
			len, R_ABS(lb-la));
	} else len = la;
	for(i = 0; i<len; i++) {
		if (a[i]!=b[i]) {
			hit++;
		} else {
			if (hit>0) {
				struct r_diff_op_t o = {
					.a_off = d->off_a+i-hit, .a_buf = a+i-hit, .a_len = hit,
					.b_off = d->off_b+i-hit, .b_buf = b+i-hit, .b_len = hit
				};
				d->callback (d, d->user, &o);
				hit = 0;
			}
		}
	}
	if (hit>0) {
		struct r_diff_op_t o = {
			.a_off = d->off_a+i-hit, .a_buf = a+i-hit, .a_len = hit,
			.b_off = d->off_b+i-hit, .b_buf = b+i-hit, .b_len = hit
		};
		d->callback (d, d->user, &o);
		hit = 0;
	}
	return 0;
}

// XXX: temporary files are
R_API int r_diff_buffers_radiff(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb) {
	char *ptr, *str, buf[64], oop = 0;
	int ret, atl, btl, hit;
	ut8 at[128], bt[128];
	ut64 ooa, oob;
	FILE *fd;

	hit = atl = btl = 0;
	ooa = oob = 0LL;
	oop = -1;

	r_file_dump (".a", a, la, 0);
	r_file_dump (".b", b, lb, 0);
	r_sys_cmd ("radiff -d .a .b | rsc uncolor > .d");
	fd = fopen (".d", "r");
	if (!fd) return 0;

	while (!feof (fd)) {
		ut64 oa, ob; // offset
		int ba, bb = 0; // byte
		char op; // operation

		oa = ob = 0LL;
		if (!fgets (buf, 63, fd))
			break;
		if (feof (fd))
			break;
		str = buf;

		ptr = strchr (buf, ' ');
		if (!ptr) continue;
		*ptr='\0';
		sscanf (str, "0x%08"PFMT64x"", &oa);

		str = r_str_ichr (ptr+1, ' ');
		if (*str!='|'&&*str!='>'&&*str!='<') {
			ptr = strchr (str, ' ');
			if (!ptr) continue;
			*ptr='\0';
			sscanf (str, "%02x", &ba);
		} else ba = 0;

		str = r_str_ichr (ptr+1, ' ');
		ptr = strchr (str, ' ');
		if (!ptr) continue;
		*ptr='\0';
		sscanf (str, "%c", &op);

		str = r_str_ichr (ptr+1, ' ');
		if (str[0]!='0' || str[1]!='x') {
			ptr = strchr(str, ' ');
			if (!ptr) continue;
			*ptr = '\0';
			sscanf (str, "%02x", &bb);
		}

		str = ptr+1;
		ptr = strchr (str, '\n');
		if (!ptr) continue;
		*ptr='\0';
		sscanf (str, "0x%08"PFMT64x"", &ob);

		if (oop == op || oop==-1) {
			if (hit == 0) {
				ooa = oa;
				oob = ob;
			}
			at[atl] = ba;
			bt[btl] = bb;
			switch (op) {
			case '|':
				atl++;
				btl++;
				break;
			case '>':
				btl++;
				break;
			case '<':
				atl++;
				break;
			}
			hit++;
		} else {
			if (hit>0) {
				struct r_diff_op_t o = {
					.a_off = ooa, .a_buf = at, .a_len = atl,
					.b_off = oob, .b_buf = bt, .b_len = btl
				};
				ret = d->callback(d, d->user, &o);
				if (!ret)
					break;
				atl = btl = 0;
				hit = 0;
			}
		}
		oop = op;
	}
	if (hit > 0) {
		struct r_diff_op_t o = {
			.a_off = ooa, .a_buf = at, .a_len = atl,
			.b_off = oob, .b_buf = bt, .b_len = btl
		};
		if (!d->callback (d, d->user, &o)) {
			fclose (fd);
			return 0;
		}
		atl = btl = 0;
		hit = 0;
	}
	fclose (fd);
	unlink (".a");
	unlink (".b");
	unlink (".d");
	return 0;
}

R_API int r_diff_buffers(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb) {
	if (d->delta) {
		return r_diff_buffers_delta (d, a, la, b, lb);
	}
	return r_diff_buffers_static (d, a, la, b, lb);
}

/* TODO: Move into r_util maybe? */
R_API bool r_diff_buffers_distance(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	const bool verbose = d? d->verbose: false;
	/* 
	More memory efficient version on Levenshtein Distance from:
	https://en.wikipedia.org/wiki/Levenshtein_distance
	http://www.codeproject.com/Articles/13525/Fast-memory-efficient-Levenshtein-algorithm
	ObM..
	*/
	int i, j;
	/* TODO: ensure those pointers are allocated */
	int *v0 = (int*) calloc ((lb + 1), sizeof (int));
	int *v1 = (int*) calloc ((lb + 1), sizeof (int));	
	
	if (!a || !b || la < 1 || lb < 1) {
		return false;
	}

	if (la == lb && !memcmp (a, b, la)) {
		if (distance) {
			*distance = 0;
		}
		if (similarity) {
			*similarity = 1.0;
		}
		return true;
	}

	for (i = 0; i < lb + 1 ; i++) {
		v0[i] = i;
	}

	for (i = 0; i < la; i++) {
		v1[0] = i + 1;

		for (j = 0; j < lb; j++) {
			int cost = (a[i] == b[j]) ? 0 : 1;
			int smallest = R_MIN ((v1[j] + 1), (v0[j + 1] + 1));
			smallest = R_MIN (smallest, (v0[j] + cost));
			v1[j + 1] = smallest;
		}

		for (j = 0; j < lb + 1; j++) {
			v0[j] = v1[j];
		}
		if (verbose && (i % 10000 == 0))
			eprintf ("Processing %d of %d\r", i, la - 1);
	}
	if (verbose) {
		eprintf ("\rProcessing %d of %d\n", i, la - 1);
	}
	
	if (distance) {
		*distance = v1[lb];
		if (similarity) {
			double diff = (double) (*distance) / (double) (R_MAX (la, lb));
			*similarity = (double)1 - diff;
		}
	}
	return true;
}
