/* radare2 - LGPL - Copyright 2019 - pancake */

#if 0

// Inspired by:

// https://www.a1k0n.net/2006/09/15/obfuscated-c-donut.html

             k;double sin()
         ,cos();main(){float A=
       0,B=0,i,j,z[1760];char b[
     1760];printf("\x1b[2J");for(;;
  ){memset(b,32,1760);memset(z,0,7040)
  ;for(j=0;6.28>j;j+=0.07)for(i=0;6.28
 >i;i+=0.02){float c=sin(i),d=cos(j),e=
 sin(A),f=sin(j),g=cos(A),h=d+2,D=1/(c*
 h*e+f*g+5),l=cos      (i),m=cos(B),n=s\
in(B),t=c*h*g-f*        e;int x=40+30*D*
(l*h*m-t*n),y=            12+15*D*(l*h*n
+t*m),o=x+80*y,          N=8*((f*e-c*d*g
 )*m-c*d*e-f*g-l        *d*n);if(22>y&&
 y>0&&x>0&&80>x&&D>z[o]){z[o]=D;;;b[o]=
 ".,-~:;=!*#$@"[N>0?N:0];}}/*#****!!-*/
  printf("\x1b[H");for(k=0;1761>k;k++)
   putchar(k%80?b[k]:10);A+=0.04;B+=
     0.02;}}/*****####*******!!=;:~
       ~::==!!!**********!!!==::-
         .,~~;;;========;;;:~-.
             ..,--------,*/

#else

#include <r_util.h>
#include <math.h>

// global iterators
R_API char *r_str_donut(int osize) {
	int size = osize;
	static float A= 0;
	static float B= 0;
	float i,j,z[1760];
	int k;
	char b[1760];
	char o[1760];
	memset (b,32,1760);
	memset (z,0,7040) ;
	if (osize == 0) {
		size = 100;
	} else {
		A=0;
		B=0;
	}
	double Zero = (((double)(100 - size) / 100) * 6);
	double Width = 30;
	double Height = 15;
	double Align = 25; // 40;
	if (osize != 0) {
		Align = 40;
	}
	for (j=Zero; 6.28>j; j+=0.07) {
		for (i=Zero;6.28 >i;i+=0.02){
			float c=sin(i);
			float d=cos(j);
			float e = sin(A);
			float f=sin(j);
			float g=cos(A);
			float h=d+2;
			float D=1/(c* h*e+f*g+5),l=cos(i),m=cos(B),n=sin(B),t=c*h*g-f*e;
			int x=Align+Width*D*(l*h*m-t*n);
			int y=12+Height*D*(l*h*n +t*m);
			int o=x+80*y;
			int N=8*((f*e-c*d*g)*m-c*d*e-f*g-l*d*n);
			if (22 >y && y > 0 && x>0&&80>x&&D>z[o]) {
				z[o] = D;
				b[o] = " .,-:!/|S$@&"[N > 0? N: 0];
			}
		}
	}
	for (k=0;k<1760;k++) {
		o[k] = k%80?b[k]:10;
	}
	o[sizeof (o) - 1] = 0;
	if (osize == 0)  {
		A += 0.03;
		B += 0.02;
	} else {
		A += 0.0000;
		B += 0.01;
	}
	char *r = strdup (o);
	r_str_trim_tail (r);
	return r;
}

#endif
