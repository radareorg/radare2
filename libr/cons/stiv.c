/* tiv - terminal image viewer - MIT 2013-2019 - pancake */

#include <r_cons.h>

#define XY(b,x,y) ( b+((y)*(w*3))+(x*3) )
#define ABS(x) (((x)<0)?-(x):(x))
#define POND(x,y) (ABS((x)) * (y))

void (*renderer)(PrintfCallback cb_printf, const ut8*, const ut8 *);

static int reduce8 (int r, int g, int b) {
	int colors_len = 8;
	int select = 0;
	int odistance = -1;
	int i, k = 1;
	int colors[][3] = {
		{ 0x00,0x00,0x00 }, // black
		{ 0xd0,0x10,0x10 }, // red
		{ 0x10,0xe0,0x10 }, // green
		{ 0xf7,0xf5,0x3a }, // yellow
		{ 0x10,0x10,0xf0 }, // blue // XXX
		{ 0xfb,0x3d,0xf8 }, // pink
		{ 0x10,0xf0,0xf0 }, // turqoise
		{ 0xf0,0xf0,0xf0 }, // white
	};

	r /= k; r *= k;
	g /= k; g *= k;
	b /= k; b *= k;
	// B&W
	if (r<30 && g<30 && b<30) return 0;
	if (r>200&& g>200&& b>200) return 7;
	odistance = -1;
	for (i = 0; i<colors_len; i++) {
		int distance =
			  POND (colors[i][0]-r, r)
			+ POND (colors[i][1]-g, g)
			+ POND (colors[i][2]-b, b);
		if (odistance == -1 || distance < odistance) {
			odistance = distance;
			select = i;
		}
	}
	return select;
}

static void render_ansi(PrintfCallback cb_printf, const ut8 *c, const ut8 *d) {
	int fg = 0;
	int color = reduce8 (c[0], c[1], c[2]);
	if (color == -1)return;
	//if (c[0]<30 && c[1]<30 && c[2]<30) fg = 1;
	cb_printf ("\x1b[%dm", color+(fg?30:40));
}

static int rgb(int r, int g, int b) {
	r = R_DIM (r, 0, 255);
	g = R_DIM (g, 0, 255);
	b = R_DIM (b, 0, 255);
	r = (int)(r/50.6); 
	g = (int)(g/50.6);
	b = (int)(b/50.6);
	return 16 + (r*36) + (g*6) + b;
}

static void render_256(PrintfCallback cb_printf, const ut8 *c, const ut8 *d) {
	cb_printf ("\x1b[%d;5;%dm", 38, rgb (c[0], c[1], c[2]));
	cb_printf ("\x1b[%d;5;%dm", 48, rgb (d[0], d[1], d[2]));
}

static void render_rgb(PrintfCallback cb_printf, const ut8 *c, const ut8 *d) {
	cb_printf ("\x1b[38;2;%d;%d;%dm", c[0], c[1], c[2]);
	cb_printf ("\x1b[48;2;%d;%d;%dm", d[0], d[1], d[2]);
}

static void render_greyscale(PrintfCallback cb_printf, const ut8 *c, const ut8 *d) {
	int color1, color2, k;
	color1 = (c[0]+c[1]+c[2]) / 3;
	color2 = (d[0]+d[1]+d[2]) / 3;
	k = 231 + ((int)((float)color1/10.3));
	if (k<232) k = 232;
	cb_printf ("\x1b[%d;5;%dm", 48, k); // bg
	k = 231 + ((int)((float)color2/10.3));
	if (k<232) k = 232;
	cb_printf ("\x1b[%d;5;%dm", 38, k); // fg
}

static void render_ascii(PrintfCallback cb_printf, const ut8 *c, const ut8 *d) {
	const char *pal = " `.,-:+*%$#";
	int idx, pal_len = strlen (pal);
	float p = (c[0]+c[1]+c[2])/3;
	float q = (d[0]+d[1]+d[2])/3;
	idx = ((p+q)/2) / (255/pal_len);
	if (idx >= pal_len) idx = pal_len-1;
	cb_printf ("%c", pal[idx]);
}

static void dorender (PrintfCallback cb_printf, const ut8 *buf, int len, int w, int h) {
	const ut8 *c, *d;
	int x, y;
	for (y=0; y<h; y+=2) {
		for (x=0; x<w; x++) {
			c = XY (buf, x, y);
			d = XY (buf, x, y+1);
			if (d> (buf+len)) break;
			renderer (cb_printf, c, d);
			if (renderer != render_ascii) {
				render_ascii (cb_printf, c, d);
			}
		}
		cb_printf ((renderer==render_ascii)?"\n":"\x1b[0m\n");
	}
}

static void selectrenderer(int mode) {
	switch (mode) {
	case 'a':
		renderer = render_ascii;
		break;
	case 'A':
		renderer = render_ansi;
		break;
	case 'g': renderer = render_greyscale; break;
	case '2': renderer = render_256; break;
	default:
		renderer = render_rgb;
		break;
	}
}

R_API void r_cons_image(const ut8 *buf, int bufsz, int width, int mode) {
	int height = (bufsz / width) / 3;
	selectrenderer (mode);
	dorender (r_cons_printf, buf, bufsz, width, height);
}

#if 0
int
main(int argc, const char **argv) {
	ut8 *buf, *c, *d;
	int n, x, y, w, h, imgsz, readsz;
	if (argc<3) {
		printf ("stiv . suckless terminal image viewer\n");
		printf ("Usage: stiv [width] [height] [ascii|ansi|grey|256|rgb] < rgb24\n");
		return 1;
	}
	w = atoi (argv[1]);
	h = atoi (argv[2]);
	if (argc>3) {
		selectrenderer (argv[3]);
	} else renderer = render_rgb;
	if (w<1 || h<1) {
		printf ("Invalid arguments\n");
		return 1;
	}
	imgsz = w * h * 3;
	buf = malloc (imgsz);
	readsz = 0;
	do {
		n = read(0, buf+readsz, imgsz);
		if (n<1) break;
		readsz += n;
	} while (readsz < imgsz);

	dorender (buf, readsz, w, h);

	free (buf);
	return 0;
}
#endif
