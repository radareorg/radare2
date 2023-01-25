/*
 * This code is originally taken from OpenSSH:
 * http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/key.c?rev=1.75&content-type=text/x-cvsweb-markup
 */

/*
 * Draw an ASCII-Art representing the fingerprint so human brain can
 * profit from its built-in pattern recognition ability.
 * This technique is called "random art" and can be found in some
 * scientific publications like this original paper:
 *
 * "Hash Visualization: a New Technique to improve Real-World Security",
 * Perrig A. and Song D., 1999, International Workshop on Cryptographic
 * Techniques and E-Commerce (CrypTEC '99)
 * sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf
 *
 * The subject came up in a talk by Dan Kaminsky, too.
 *
 * If you see the picture is different, the key is different.
 * If the picture looks the same, you still know nothing.
 *
 * The algorithm used here is a worm crawling over a discrete plane,
 * leaving a trace (augmenting the field) everywhere it goes.
 * Movement is taken from dgst_raw 2bit-wise.  Bumping into walls
 * makes the respective movement vector be ignored for this turn.
 * Graphs are not unambiguous, because circles in graphs can be
 * walked in either direction.
 */

/*
 * Field sizes for the random art.  Have to be odd, so the starting point
 * can be in the exact middle of the picture, and FLDBASE should be >=8 .
 * Else pictures would be too dense, and drawing the frame would
 * fail, too, because the key type would not fit in anymore.
 */
#include <r_util.h>

#define	FLDBASE		8
#define	FLDSIZE_Y	(FLDBASE + 1)
#define	FLDSIZE_X	(FLDBASE * 2 + 1)

//static char * key_fingerprint_randomart(ut8 *dgst_raw, ut32 dgst_raw_len) {
R_API char *r_print_randomart(const ut8 *dgst_raw, ut32 dgst_raw_len, ut64 addr) {
	/*
	 * Chars to be used after each other every time the worm
	 * intersects with itself.  Matter of taste.
	 */
	char *augmentation_string = " .o+=*BOX@%&#/^SE";
	char *p;
	ut8 field[FLDSIZE_X][FLDSIZE_Y];
	ut32 i, b;
	size_t len = strlen (augmentation_string) - 1;
	// 2*(FLDSIZE_X+3) there are two for loops that iterate over this
	// FLDSIZE_Y * (FLDSIZE_X+3) there is a loop that for each y iterates over the whole FLDSIZE_X
	// The rest is counting the +--[0x%08"PFMT64x"]- and '\0'
	size_t retval_sz = 2 * (FLDSIZE_X + 3) + (FLDSIZE_Y * (FLDSIZE_X+3))+ 7 + sizeof (PFMT64x);
	char *retval = calloc (1, retval_sz);

	/* initialize field */
	memset (field, 0, FLDSIZE_X * FLDSIZE_Y * sizeof (char));
	int x = FLDSIZE_X / 2;
	int y = FLDSIZE_Y / 2;

	/* process raw key */
	for (i = 0; i < dgst_raw_len; i++) {
		/* each byte conveys four 2-bit move commands */
		int input = dgst_raw[i];
		for (b = 0; b < 4; b++) {
			/* evaluate 2 bit, rest is shifted later */
			x += (input & 0x1) ? 1 : -1;
			y += (input & 0x2) ? 1 : -1;

			/* assure we are still in bounds */
			x = R_MAX (x, 0);
			y = R_MAX (y, 0);
			x = R_MIN (x, FLDSIZE_X - 1);
			y = R_MIN (y, FLDSIZE_Y - 1);

			/* augment the field */
			if (field[x][y] < len - 2) {
				field[x][y]++;
			}
			input = input >> 2;
		}
	}

	/* mark starting point and end point*/
	field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = len - 1;
	field[x][y] = len;

	/* fill in retval */
	snprintf (retval, retval_sz, "+--[0x%08"PFMT64x"]-", addr);
	p = strchr (retval, '\0');

	/* output upper border */
	for (i = p - retval - 1; i < FLDSIZE_X; i++) {
		*p++ = '-';
	}
	*p++ = '+';
	*p++ = '\n';

	/* output content */
	for (y = 0; y < FLDSIZE_Y; y++) {
		*p++ = '|';
		for (x = 0; x < FLDSIZE_X; x++) {
			*p++ = augmentation_string[R_MIN (field[x][y], len)];
		}
		*p++ = '|';
		*p++ = '\n';
	}

	/* output lower border */
	*p++ = '+';
	for (i = 0; i < FLDSIZE_X; i++) {
		*p++ = '-';
	}
	*p++ = '+';
	*p++ = 0;

	return retval;
}
