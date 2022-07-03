/* radare2 - LGPL - Copyright 2019 - pancake */

// https://www.a1k0n.net/2006/09/15/obfuscated-c-donut.html

#include <r_util.h>
#include <math.h>

// global iterators
R_API char *r_str_donut(int osize) {
	int size = osize;
	static R_TH_LOCAL float A = 0;
	static R_TH_LOCAL float B = 0;
	float i,j,z[1760];
	int k;
	char b[1760];
	char o[1760];
	memset (b, 32, 1760);
	memset (z, 0, 7040) ;
	if (osize == 0) {
		size = 100;
	} else {
		A = B = 0;
	}
	float Zero = (((float)(100 - size) / 100) * 6);
	float Width = 30;
	float Height = 15;
	float Align = 25; // 40;
	if (osize != 0) {
		Align = 40;
	}
	for (j = Zero; 6.28f > j; j += 0.07f) {
		for (i = Zero; 6.28f > i; i+= 0.02f) {
			float c = sin (i);
			float d = cos (j);
			float e = sin (A);
			float f = sin (j);
			float g = cos (A);
			float h = d + 2;
			float D = 1 / (c* h*e+f*g+5);
			float l = cos (i);
			float m = cos (B);
			float n = sin (B);
			float t = c*h*g-f*e;
			int x = (int)(Align+Width*D*(l*h*m-t*n));
			int y = (int)(12 + Height*D*(l*h*n +t*m));
			int o = x + 80 * y;
			int N = (int)(8 * ((f*e-c*d*g)*m-c*d*e-f*g-l*d*n));
			if (22 > y && y > 0 && x > 0 && 80 > x && D > z[o]) {
				z[o] = D;
				b[o] = " .,-:!/|S$@&"[N > 0? N: 0];
			}
		}
	}
	for (k = 0; k < 1760; k++) {
		o[k] = (k % 80)? b[k]: 10;
	}
	o[sizeof (o) - 1] = 0;
	if (osize == 0)  {
		A += 0.03f;
		B += 0.02f;
	} else {
		A += 0.0f;
		B += 0.01f;
	}
	char *r = strdup (o);
	r_str_trim_tail (r);
	return r;
}
