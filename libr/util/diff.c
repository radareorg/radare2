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

R_API bool r_diff_buffers_distance_levenstein(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	const bool verbose = d? d->verbose: false;
	/*
	More memory efficient version on Levenshtein Distance from:
	https://en.wikipedia.org/wiki/Levenshtein_distance
	http://www.codeproject.com/Articles/13525/Fast-memory-efficient-Levenshtein-algorithm
	ObM..

	8/July/2016 - More time efficient Levenshtein Distance. Now runs in about O(N*sum(MDistance)) instead of O(NM)
	In real world testing the speedups for similar files are immense. Processing of
	radiff2 -sV routerA/firmware_extract/bin/httpd routerB/firmware_extract/bin/httpd
	reduced from 28 hours to about 13 minutes.
	*/
	int i, j;
	const ut8 *aBufPtr;
	const ut8 *bBufPtr;
	ut32 aLen;
	ut32 bLen;

	// temp pointer will be used to switch v0 and v1 after processing the inner loop.
	int *temp;
	int *v0, *v1;

	// We need these variables outside the context of the loops as we need to
	// survive multiple loop iterations.
	// start and stop are used in our inner loop
	// colMin tells us the current 'best' edit distance.
	// extendStop & extendStart are used when we get 'double up' edge conditions
	// that require us to keep some more data.
	int start = 0;
	int stop = 0;
	int smallest;
	int colMin = 0;
	int extendStop = 0;
	int extendStart = 0;

	//we could move cost into the 'i' loop.
	int cost = 0;

	// loops can get very big, this can be removed, but it's currently in there for debugging
	// and optimisation testing.
	ut64 loops = 0;

	// We need the longest file to be 'A' because our optimisation tries to stop and start
	// around the diagonal.
	//  AAAAAAA
	// B*
	// B *
	// B  *____
	// if we have them the other way around and we terminate on the diagonal, we won't have
	// inspected all the bytes of file B..
	//  AAAA
	// B*
	// B *
	// B  *
	// B   *
	// B   ?

	if (la < lb) {
		aBufPtr = b;
		bBufPtr = a;
		aLen = lb;
		bLen = la;
	} else {
		aBufPtr = a;
		bBufPtr = b;
		aLen = la;
		bLen = lb;
	}
	stop = bLen;
	// Preliminary tests

	//Do we have both files a & b, and are they at least one byte?
	if (!aBufPtr || !bBufPtr || aLen < 1 || bLen < 1) {
		return false;
	}

	//IF the files are the same size and are identical, then we have matching files
	if (aLen == bLen && !memcmp (aBufPtr, bBufPtr, aLen)) {
		if (distance) {
			*distance = 0;
		}
		if (similarity) {
			*similarity = 1.0;
		}
		return true;
	}
	// Only calloc if we have to do some processing

	// calloc v0 & v1 and check they initialised
	v0 = (int*) calloc ((bLen + 3), sizeof (int));
	if (!v0) {
		eprintf ("Error: cannot allocate %i bytes.", bLen + 3);
		return false;
	}

	v1 = (int*) calloc ((bLen + 3), sizeof (int));
	if (!v1) {
		eprintf ("Error: cannot allocate %i bytes", 2 * (bLen + 3));
		free (v0);
		return false;
	}

	// initialise v0 and v1.
	// With optimisiation we only strictly we only need to initialise v0[0..2]=0..2 & v1[0] = 1;
	for (i = 0; i < bLen + 1 ; i++) {
		v0[i] = i;
		v1[i] = i + 1;
	}

	// Outer loop = the length of the longest input file.
	for (i = 0; i < aLen; i++) {

		// We're going to stop the inner loop at:
		// bLen (so we don't run off the end of our array)
		// or 'two below the diagonal' PLUS any extension we need for 'double up' edge values
		// (see extendStop for logic)
		stop = R_MIN ((i + extendStop + 2), bLen);

		// We need a value in the result column (v1[start]).
		// If you look at the loop below, we need it because we look at v1[j] as one of the
		// potential shortest edit distances.
		// In all cases where the edit distance can't 'reach',
		// the value of v1[start] simply increments.
		if (start > bLen) {
			break;
		} 
		v1[start] = v0[start] + 1;

		// need to have a bigger number in colMin than we'll ever encounter in the inner loop
		colMin = aLen;

		// Inner loop does all the work:
		for (j = start; j <= stop; j++) {
			loops++;

			// The main levenshtein comparison:
			cost = (aBufPtr[i] == bBufPtr[j]) ? 0 : 1;
			smallest = R_MIN ((v1[j] + 1), (v0[j + 1] + 1));
			smallest = R_MIN (smallest, (v0[j] + cost));

			// populate the next two entries in v1.
			// only really required if this is the last loop.
			if (j + 2 > bLen + 3) {
				break;
			}
			v1[j + 1] = smallest;
			v1[j + 2] = smallest + 1;

			// If we have seen a smaller number, it's the new column Minimum
			colMin = R_MIN ((colMin), (smallest));

		}

		// We're going to start at i+1 next iteration
		// The column minimum is the current edit distance
		// This distance is the minimum 'search width' from the optimal 'i' diagonal
		// The extendStart picks up an edge case where we have a match on the first iteration
		// We update extendStart after we've set start for the next iteration.
		start = i + 1 - colMin - extendStart;

		// If the last processed entry is a match, AND
		// the current byte in 'a' and the previous processed entry in 'b' aren't a match
		// then we need to extend our search below the optimal 'i' diagonal. because we'll
		// have a vertical double up condition in our last two values of the results column.
		// j-2 is used because j++ increments prior to loop exit in the processing loop above.
		if (!cost && aBufPtr[i] != bBufPtr[j - 2]) {
			extendStop ++;
		}

		// If new start would be a match then we have a horizontal 'double up'
		// which means we need to keep an extra row of data
		// so don't increment the start counter this time, BUT keep
		// extendStart up our sleeves for next iteration.
		if (i + 1 < aLen && start < bLen && aBufPtr[i + 1] == bBufPtr[start]) {
			start --;
			extendStart ++;
		}
		//Switch v0 and v1 pointers via temp pointer
		temp = v0;
		v0 = v1;
		v1 = temp;

		//Print a processing update every 10K of outer loop
		if (verbose && i % 10000==0) {
			eprintf ("\rProcessing %d of %d\r", i, aLen);
		}
	}
	//Clean up output on loop exit (purely aesthetic)
	if (verbose) {
		eprintf ("\rProcessing %d of %d (loops=%llu)\n", i, aLen,loops);
	}
	if (distance) {
		// the final distance is the last byte we processed in the inner loop.
		// v0 is used instead of v1 because we switched the pointers before exiting the outer loop
		*distance = v0[stop];
		if (similarity) {
			double diff = (double) (*distance) / (double) (R_MAX (aLen, bLen));
			*similarity = (double)1 - diff;
		}
	}
	free (v0);
	free (v1);
	return true;
}

R_API bool r_diff_buffers_distance_original(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	int i, j, tmin, **m;
	ut64 totalsz = 0;

	if (!a || !b || la < 1 || lb < 1)
		return false;

	if (la == lb && !memcmp (a, b, la)) {
		if (distance != NULL)
			*distance = 0;
		if (similarity != NULL)
			*similarity = 1.0;
		return true;
	}
	totalsz = sizeof(int*) * (lb+1);
	for(i = 0; i <= la; i++) {
		totalsz += ((lb+1) * sizeof(int));
	}
	if (totalsz >= 1024 * 1024 * 1024) { // 1 GB of ram
		char *szstr = r_num_units (NULL, totalsz);
		eprintf ("Too much memory required (%s) to run distance diff, Use -c.\n", szstr);
		free (szstr);
		return false;
	}
	if ((m = malloc ((la+1) * sizeof(int*))) == NULL)
		return false;
	for(i = 0; i <= la; i++) {
		if ((m[i] = malloc ((lb+1) * sizeof(int))) == NULL) {
			eprintf ("Allocation failed\n");
			while (i--)
				free (m[i]);
			free (m);
			return false;
		}
	}

	for (i = 0; i <= la; i++)
		m[i][0] = i;
	for (j = 0; j <= lb; j++)
		m[0][j] = j;

	for (i = 1; i <= la; i++) {
		for (j = 1; j <= lb; j++) {
			int cost = (a[i-1] != b[j-1])? 1: 0;
			tmin = R_MIN (m[i-1][j] + 1, m[i][j-1] + 1);
			m[i][j] = R_MIN (tmin, m[i-1][j-1] + cost);
		}
	}

	if (distance) {
		*distance = m[la][lb];
	}
	if (similarity) {
		*similarity = (double)1 - (double)(m[la][lb])/(double)(R_MAX(la, lb));
	}

	for(i = 0; i <= la; i++) {
		free (m[i]);
	}
	free (m);

	return true;
}

R_API bool r_diff_buffers_distance(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity) {
	if (d && d->levenstein) {
		return r_diff_buffers_distance_levenstein (d, a, la, b, lb, distance, similarity);
	}
	return r_diff_buffers_distance_original (d, a, la, b, lb, distance, similarity);
}
