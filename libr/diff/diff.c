/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_diff.h>

R_LIB_VERSION (r_diff);

R_API RDiff *r_diff_new(ut64 off_a, ut64 off_b) {
	RDiff *d = R_NEW (RDiff);
	if (d) {
		d->delta = 1;
		d->user = NULL;
		d->off_a = off_a;
		d->off_b = off_b;
	}
	return d;
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

	r_file_dump (".a", a, la);
	r_file_dump (".b", b, lb);
	r_sys_cmd ("radiff -d .a .b | rsc uncolor > .d");
	fd = fopen (".d", "r");

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
					break;
				atl = btl = 0;
				hit = 0;
				if (!ret)
					break;
			}
		}
		oop = op;
	}
	if (hit>0) {
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
	if (d->delta)
		return r_diff_buffers_delta (d, a, la, b, lb);
	return r_diff_buffers_static (d, a, la, b, lb);
}

/* TODO: Move into r_util maybe? */
R_API int r_diff_buffers_distance(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb,
		ut32 *distance, double *similarity) {
	int i, j, cost, tmin, **m;

	if (!a || !b || la < 1 || lb < 1)
		return R_FALSE;

	if ((m = malloc ((la+1) * sizeof(int*))) == NULL)
		return R_FALSE;
	for(i = 0; i <= la; i++)
		if ((m[i] = malloc ((lb+1) * sizeof(int))) == NULL) {
			while (i--)
				free (m[i]);
			free (m);
			return R_FALSE;
		}

	for (i = 0; i <= la; i++)
		m[i][0] = i;
	for (j = 0; j <= lb; j++)
		m[0][j] = j;

	for (i = 1; i <= la; i++) {
		for (j = 1; j <= lb; j++) {
			if (a[i-1] == b[j-1])
				cost = 0;
			else cost = 1;
			tmin = R_MIN (m[i-1][j] + 1, m[i][j-1] + 1);
			m[i][j] = R_MIN (tmin, m[i-1][j-1] + cost);
		}
	}

	if (distance != NULL)
		*distance = m[la][lb];
	if (similarity != NULL) {
		if (la == 0 || lb == 0)
			*similarity = 0;
		else
			*similarity = (double)1 - (double)(m[la][lb])/(double)(R_MAX(la, lb));
	}

	for(i = 0; i <= la; i++)
		free (m[i]);
	free (m);

	return R_TRUE;
}
