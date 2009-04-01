/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_diff.h>

R_API struct r_diff_t *r_diff_new(u64 off_a, u64 off_b)
{
	struct r_diff_t *d = MALLOC_STRUCT(struct r_diff_t);
	r_diff_init(d, off_a, off_b);
	return d;
}

R_API int r_diff_init(struct r_diff_t *d, u64 off_a, u64 off_b)
{
	d->delta = 1;
	d->user = NULL;
	d->off_a = off_a;
	d->off_b = off_b;
	return 1;
}

R_API struct r_diff_t *r_diff_free(struct r_diff_t *d)
{
	free(d);
	return NULL;
}

R_API int r_diff_set_callback(struct r_diff_t *d,
	int (*callback)(struct r_diff_t *d, void *user, struct r_diff_op_t *op),
	void *user)
{
	d->callback = callback;
	d->user = user;
	return 1;
}

R_API int r_diff_set_delta(struct r_diff_t *d, int delta)
{
	d->delta = delta;
	return 1;
}

R_API int r_diff_buffers_static(struct r_diff_t *d, const u8 *a, int la, const u8 *b, int lb)
{
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
				d->callback(d, d->user, &o);
				hit = 0;
			}
		}
	}
	if (hit>0) {
		struct r_diff_op_t o = {
			.a_off = d->off_a+i-hit, .a_buf = a+i-hit, .a_len = hit,
			.b_off = d->off_b+i-hit, .b_buf = b+i-hit, .b_len = hit 
		};
		d->callback(d, d->user, &o);
		hit = 0;
	}
	return 0;
}

R_API int r_diff_buffers_delta(struct r_diff_t *d, const u8 *a, int la, const u8 *b, int lb)
{
	char buf[64];
	char *ptr;
	char *str;
	FILE *fd;
	char oop = 0;
	int atl, btl, hit;
	u8 at[128];
	u8 bt[128];
	u64 ooa, oob;

	hit = atl = btl = 0;
	ooa = oob = 0LL;
	oop = -1;

	r_file_dump(".a", a, la);
	r_file_dump(".b", b, lb);
	system("radiff -d .a .b | rsc uncolor > .d");
	fd = fopen(".d", "r");

	while(!feof(fd)) {
		u64 oa, ob; // offset
		int ba, bb; // byte
		char op; // operation

		oa = ob = 0LL;
		fgets(buf, 63, fd);
		if (feof(fd))
			break;
		str = buf;

		ptr = strchr(buf, ' ');
		if (!ptr) continue;
		*ptr='\0';
		sscanf(str, "0x%08llx", &oa);

		str = r_str_ichr(ptr+1, ' ');
		if (*str!='|'&&*str!='>'&&*str!='<') {
			ptr = strchr(str, ' ');
			if (!ptr) continue;
			*ptr='\0';
			sscanf(str, "%02x", &ba);
		} else ba = 0;

		str = r_str_ichr(ptr+1, ' ');
		ptr = strchr(str, ' ');
		if (!ptr) continue;
		*ptr='\0';
		sscanf(str, "%c", &op);

		str = r_str_ichr(ptr+1, ' ');
		if (str[0]!='0'||str[1]!='x') {
			ptr = strchr(str, ' ');
			if (!ptr) continue;
			*ptr='\0';
			sscanf(str, "%02x", &bb);
		}

		str = ptr+1;
		ptr = strchr(str, '\n');
		if (!ptr) continue;
		*ptr='\0';
		sscanf(str, "0x%08llx", &ob);

		if (oop == op || oop==-1) {
			if (hit == 0) {
				ooa = oa;
				oob = ob;
			}
			at[atl]=ba;
			bt[btl]=bb;
			switch(op) {
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
				/* run callback */
				d->callback(d, d->user, &o);
				atl = btl = 0;
				hit = 0;
			}
		}
		oop = op;
	}
	if (hit>0) {
		struct r_diff_op_t o = {
			.a_off = ooa, .a_buf = at, .a_len = atl,
			.b_off = oob, .b_buf = bt, .b_len = btl
		};
		/* run callback */
		d->callback(d, d->user, &o);
		atl = btl = 0;
		hit = 0;
	}
	fclose(fd);
	unlink(".a");
	unlink(".b");
	unlink(".d");
	return 0;
}

R_API int r_diff_buffers(struct r_diff_t *d, const u8 *a, u32 la, const u8 *b, u32 lb)
{
	int ret;

	if (d->delta) {
		fprintf(stderr, "Cannot diff different size buffers yet\n");
		ret = r_diff_buffers_delta(d, a, la, b, lb);
	} else ret = r_diff_buffers_static(d, a, la, b, lb);

	return ret;
}

/* TODO: Move into r_util maybe? */
R_API int r_diff_buffers_distance(struct r_diff_t *d, const u8 *a, u32 la, const u8 *b, u32 lb, u32 *distance, double *similarity)
{
	int i, j, cost, tmin, **m;

	if (la < 1 || lb < 1)
		return R_FALSE;

	if ((m = alloca(la * sizeof(int*))) == NULL)
		return R_FALSE;
	for(i = 0; i <= la; i++)
		if ((m[i] = alloca(lb * sizeof(int))) == NULL)
			return R_FALSE;

	for (i = 0; i <= la; i++)
		m[i][0] = i;
	for (j = 0; j <= lb; j++)
		m[0][j] = j;

	for (i = 1; i <= la; i++) {
		for (j = 1; j <= lb; j++) {
			if (a[i-1] == b[j-1])
				cost = 0;
			else cost = 1;

			tmin = R_MIN(m[i-1][j] + 1, m[i][j-1] + 1);
			m[i][j] = R_MIN(tmin, m[i-1][j-1] + cost);
		}
	}
	
	if (distance != NULL)
		*distance = m[la][lb];
	if (similarity != NULL)
		*similarity = 1.0/(1.0+m[la][lb]);

	return R_TRUE;
}
