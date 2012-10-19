// original code from:
//====================
// advanced encryption standard
// author: karl malbrain, malbrain@yahoo.com
//
// adapted from Christophe Devine's tables
// and George Anescu's c++ code.

#include <r_crypto.h>

typedef unsigned char uchar;

#include <memory.h>
#define Nb 4			// number of columns in the state & expanded key

#define Nk 4			// number of columns in a key
#define Nr 10			// number of rounds in encryption
#define AES_KEY (4 * Nk)
#define ROUND_KEY_COUNT ((Nr + 1) * 4)

#include "crypto_aes_algo.h"

static const uchar Rcon[30] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xc0, 
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 
	0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 
	0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
};

//Expand a user-supplied key material into a session key.
// key        - The 128/192/256-bit user-key to use.

void aes_expkey(uchar *key, unsigned expkey[2][Nr+1][Nb]) {
unsigned tk[Nk], tt; 
int idx = 0, t = 0;
int i, j, r;

	for( i = 0; i <= Nr; i++ )
		for(j=0; j<Nb; j++)
			expkey[0][i][j] = 0;

	for( i = 0; i <= Nr; i++)
		for(j=0; j<Nb; j++)
			expkey[1][i][j] = 0;

	//Copy user material bytes into temporary ints
	for( i = 0; i < Nk; i++ )
	{
		tk[i] = *key++ << 24;
		tk[i] |= *key++ << 16;
		tk[i] |= *key++ << 8;
		tk[i] |= *key++;
	}

	//Copy values into round key arrays
	for( j = 0; j < Nk && t < ROUND_KEY_COUNT; j++, t++ )
	{
		expkey[0][t/Nb][t%Nb] = tk[j];
		expkey[1][Nr - (t/Nb)][t%Nb] = tk[j];
	}

	while( t < ROUND_KEY_COUNT )
	{
		//Extrapolate using phi (the round key evolution function)
		tt = tk[Nk-1];
		tk[0] ^= Sbox[(uchar)(tt >> 16)] << 24 ^
			Sbox[(uchar)(tt >>  8)] << 16 ^
			Sbox[(uchar) tt] <<  8 ^
			Sbox[(uchar)(tt >> 24)] ^
			Rcon[idx++] << 24;

        if ( Nk != 8 )
		  for( i=1, j=0; i < Nk; )
			tk[i++] ^= tk[j++];
        else {
          for( i = 1, j = 0; i < Nk / 2; )
		    tk[i++] ^= tk[j++];
          tt = tk[Nk / 2 - 1];
          tk[Nk / 2] ^= Sbox[(uchar)  tt        ]       ^
                        Sbox[(uchar)( tt >>  8 )] <<  8 ^
                        Sbox[(uchar)( tt >> 16 )] << 16 ^
                        Sbox[(uchar)( tt >> 24 )] << 24;
          for( j = Nk / 2, i = j + 1; i < Nk; )
		    tk[i++] ^= tk[j++];
	    }

		//Copy values into round key arrays
		for( j = 0; j < Nk && t < ROUND_KEY_COUNT; j++, t++ )
		{
			expkey[0][t/Nb][t%Nb] = tk[j];
			expkey[1][Nr - (t/Nb)][t%Nb] = tk[j];
		}
	}

	//Inverse MixColumn where needed

	for( r = 1; r < Nr; r++ )
 		for( j = 0; j < Nb; j++ )
		{
			tt = expkey[1][r][j];
			expkey[1][r][j] = U0[(uchar)(tt >> 24)] ^
				U1[(uchar)(tt >> 16)] ^
				U2[(uchar)(tt >>  8)] ^
				U3[(uchar)tt];
		}
}

//Convenience method to encrypt exactly one block of plaintext, assuming
//Rijndael's default block size (128-bit).
// in         - The plaintext
// result     - The ciphertext generated from a plaintext using the key
void aes_encrypt(uchar* in, unsigned expkey[2][Nr+1][Nb], uchar* result)
{
	unsigned t0, t1, t2, t3, tt; 
	unsigned a0, a1, a2, a3, r;

	t0 = *in++ << 24;
	t0 |= *in++ << 16;
	t0 |= *in++ << 8;
	t0 |= *in++;
	t0 ^= expkey[0][0][0];
	
	
	t1 = *in++ << 24;
	t1 |= *in++ << 16;
	t1 |= *in++ << 8;
	t1 |= *in++;
	t1 ^= expkey[0][0][1];
	
	t2 = *in++ << 24;
	t2 |= *in++ << 16;
	t2 |= *in++ << 8;
	t2 |= *in++;
	t2 ^= expkey[0][0][2];
	
	t3 = *in++ << 24;
	t3 |= *in++ << 16;
	t3 |= *in++ << 8;
	t3 |= *in++;
	t3 ^= expkey[0][0][3];

	//Apply Round Transforms
	for( r = 1; r < Nr; r++ )
	{
		a0 = (FT0[(uchar)(t0 >> 24)] ^
			FT1[(uchar)(t1 >> 16)] ^
			FT2[(uchar)(t2 >>  8)] ^
			FT3[(uchar)t3]);
		a1 = (FT0[(uchar)(t1 >> 24)] ^
			FT1[(uchar)(t2 >> 16)] ^
			FT2[(uchar)(t3 >>  8)] ^
			FT3[(uchar)t0]);
		a2 = (FT0[(uchar)(t2 >> 24)] ^
			FT1[(uchar)(t3 >> 16)] ^
			FT2[(uchar)(t0 >>  8)] ^
			FT3[(uchar)t1]);
		a3 = (FT0[(uchar)(t3 >> 24)] ^
			FT1[(uchar)(t0 >> 16)] ^
			FT2[(uchar)(t1 >>  8)] ^
			FT3[(uchar)t2]);
		t0 = a0 ^ expkey[0][r][0];
		t1 = a1 ^ expkey[0][r][1];
		t2 = a2 ^ expkey[0][r][2];
		t3 = a3 ^ expkey[0][r][3];
	}

	//Last Round is special

	tt = expkey[0][Nr][0];
	result[0] = Sbox[(uchar)(t0 >> 24)] ^ (uchar)(tt >> 24);
	result[1] = Sbox[(uchar)(t1 >> 16)] ^ (uchar)(tt >> 16);
	result[2] = Sbox[(uchar)(t2 >>  8)] ^ (uchar)(tt >>  8);
	result[3] = Sbox[(uchar)t3] ^ (uchar)tt;

	tt = expkey[0][Nr][1];
	result[4] = Sbox[(uchar)(t1 >> 24)] ^ (uchar)(tt >> 24);
	result[5] = Sbox[(uchar)(t2 >> 16)] ^ (uchar)(tt >> 16);
	result[6] = Sbox[(uchar)(t3 >>  8)] ^ (uchar)(tt >>  8);
	result[7] = Sbox[(uchar)t0] ^ (uchar)tt;

	tt = expkey[0][Nr][2];
	result[8] = Sbox[(uchar)(t2 >> 24)] ^ (uchar)(tt >> 24);
	result[9] = Sbox[(uchar)(t3 >> 16)] ^ (uchar)(tt >> 16);
	result[10] = Sbox[(uchar)(t0 >>  8)] ^ (uchar)(tt >>  8);
	result[11] = Sbox[(uchar)t1] ^ (uchar)tt;

	tt = expkey[0][Nr][3];
	result[12] = Sbox[(uchar)(t3 >> 24)] ^ (uchar)(tt >> 24);
	result[13] = Sbox[(uchar)(t0 >> 16)] ^ (uchar)(tt >> 16);
	result[14] = Sbox[(uchar)(t1 >>  8)] ^ (uchar)(tt >>  8);
	result[15] = Sbox[(uchar)t2] ^ (uchar)tt;
}

//Convenience method to decrypt exactly one block of plaintext, assuming
//Rijndael's default block size (128-bit).
// in         - The ciphertext.
// result     - The plaintext generated from a ciphertext using the session key.
void aes_decrypt(uchar* in, unsigned expkey[2][Nr+1][Nb], uchar* result)
{
unsigned t0, t1, t2, t3, tt; 
unsigned a0, a1, a2, a3, r;

	t0 = *in++ << 24;
	t0 |= *in++ << 16;
	t0 |= *in++ << 8;
	t0 |= *in++;
	t0 ^= expkey[1][0][0];
	
	t1 = *in++ << 24;
	t1 |= *in++ << 16;
	t1 |= *in++ << 8;
	t1 |= *in++;
	t1 ^= expkey[1][0][1];
	
	t2 = *in++ << 24;
	t2 |= *in++ << 16;
	t2 |= *in++ << 8;
	t2 |= *in++;
	t2 ^= expkey[1][0][2];
	
	t3 = *in++ << 24;
	t3 |= *in++ << 16;
	t3 |= *in++ << 8;
	t3 |= *in++;
	t3 ^= expkey[1][0][3];
	
	for( r = 1; r < Nr; r++ ) // apply round transforms
	{
		a0 = (RT0[(uchar)(t0 >> 24)] ^
			RT1[(uchar)(t3 >> 16)] ^
			RT2[(uchar)(t2 >>  8)] ^
			RT3[(uchar) t1       ] );
		a1 = (RT0[(uchar)(t1 >> 24)] ^
			RT1[(uchar)(t0 >> 16)] ^
			RT2[(uchar)(t3 >>  8)] ^
			RT3[(uchar) t2       ] );
		a2 = (RT0[(uchar)(t2 >> 24)] ^
			RT1[(uchar)(t1 >> 16)] ^
			RT2[(uchar)(t0 >>  8)] ^
			RT3[(uchar) t3       ] );
		a3 = (RT0[(uchar)(t3 >> 24)] ^
			RT1[(uchar)(t2 >> 16)] ^
			RT2[(uchar)(t1 >>  8)] ^
			RT3[(uchar) t0       ] );
		t0 = a0 ^ expkey[1][r][0];
		t1 = a1 ^ expkey[1][r][1];
		t2 = a2 ^ expkey[1][r][2];
		t3 = a3 ^ expkey[1][r][3];
	}

	//Last Round is special
	tt = expkey[1][Nr][0];
	result[ 0] = InvSbox[(uchar)(t0 >> 24)] ^ (uchar)(tt >> 24);
	result[ 1] = InvSbox[(uchar)(t3 >> 16)] ^ (uchar)(tt >> 16);
	result[ 2] = InvSbox[(uchar)(t2 >>  8)] ^ (uchar)(tt >>  8);
	result[ 3] = InvSbox[(uchar) t1] ^ (uchar)tt;

	tt = expkey[1][Nr][1];
	result[ 4] = InvSbox[(uchar)(t1 >> 24)] ^ (uchar)(tt >> 24);
	result[ 5] = InvSbox[(uchar)(t0 >> 16)] ^ (uchar)(tt >> 16);
	result[ 6] = InvSbox[(uchar)(t3 >>  8)] ^ (uchar)(tt >>  8);
	result[ 7] = InvSbox[(uchar) t2] ^ (uchar)tt;

	tt = expkey[1][Nr][2];
	result[ 8] = InvSbox[(uchar)(t2 >> 24)] ^ (uchar)(tt >> 24);
	result[ 9] = InvSbox[(uchar)(t1 >> 16)] ^ (uchar)(tt >> 16);
	result[10] = InvSbox[(uchar)(t0 >>  8)] ^ (uchar)(tt >>  8);
	result[11] = InvSbox[(uchar) t3] ^ (uchar)tt;

	tt = expkey[1][Nr][3];
	result[12] = InvSbox[(uchar)(t3 >> 24)] ^ (uchar)(tt >> 24);
	result[13] = InvSbox[(uchar)(t2 >> 16)] ^ (uchar)(tt >> 16);
	result[14] = InvSbox[(uchar)(t1 >>  8)] ^ (uchar)(tt >>  8);
	result[15] = InvSbox[(uchar) t0] ^ (uchar)tt;
}

#ifdef STANDALONE

#include <stdio.h>
#include <fcntl.h>
uchar in[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

uchar key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

uchar out[16];

typedef unsigned long long __int64;

unsigned long long rd_clock () {
	unsigned long long dwBoth;
	__asm__ volatile(".byte 0x0f, 0x31" : "=A"(dwBoth)); 
	return dwBoth;
}

void certify () {
	unsigned expkey[2][Nr + 1][Nb], idx, diff;
	__int64 start, stop;

	aes_expkey (key, expkey);
	aes_encrypt (in, expkey, out);

	start = rd_clock();

	aes_encrypt (in, expkey, out);

	stop = rd_clock();
	diff = stop - start;
	printf ("encrypt time: %d, %d cycles per byte\n", diff, diff/16);

	for( idx = 0; idx < 16; idx++ )
		printf ("%.2x ", out[idx]);

	printf ("\n");
	aes_decrypt (out, expkey, in);
	start = rd_clock();
	aes_decrypt (out, expkey, in);

	stop = rd_clock();
	diff = stop - start;
	printf ("decrypt time: %d, %d cycles per byte\n", diff, diff/16);

	for( idx = 0; idx < 16; idx++ )
		printf ("%.2x ", in[idx]);

	printf ("\n");
}

void decrypt (char *mykey, char *name) {
	unsigned expkey[2][Nr + 1][Nb];
	FILE *fd = r_sandbox_fopen (name, "rb");
	int ch, idx = 0;

	strncpy (key, mykey, sizeof (key)-1);
	aes_expkey (key, expkey);

	while( ch = getc(fd), ch != EOF ) {
		in[idx++] = ch;
		if( idx % 16 )
			continue;

		aes_decrypt (in, expkey, out);

		for( idx = 0; idx < 16; idx++ )
			putchar (out[idx]);
		idx = 0;
	}
}

void encrypt (char *mykey, char *name)
{
	unsigned expkey[2][Nr + 1][Nb];
	FILE *fd = r_sandbox_fopen (name, "rb");
	int ch, idx = 0;

	strncpy (key, mykey, sizeof (key)-1);
	aes_expkey (key, expkey);

	while( ch = getc(fd), ch != EOF ) {
		in[idx++] = ch;
		if( idx % 16 )
			continue;

		aes_encrypt (in, expkey, out);

		for( idx = 0; idx < 16; idx++ )
			putchar (out[idx]);
		idx = 0;
	}

	if( idx )
	  while( idx % 16 )
		in[idx++] = 0;
	else
	  return;

	aes_encrypt (in, expkey, out);

	for( idx = 0; idx < 16; idx++ )
		putchar (out[idx]);
}

#ifndef unix
unsigned expkey[2][Nr + 1][Nb];
void mrandom (int, char *);
unsigned xrandom (void);

int aescycles ()
{
__int64 start, end;
int t;

	do {
		start = rd_clock();
		aes_encrypt (in, expkey, out);
		end = rd_clock ();
		t = end - start;
	} while( t<= 0 || t>= 4000);
	return t;
}

int bestx (int b, int loops)
{
int bestx = 0, bestxt = 0;
int x, xt, i, j;

	for( x = 0; x < 256; x++ ) {
		xt = 0;
		for( i = 0; i < loops; i++ ) {
			for( j = 0; j < 16; j++ )
				in[j] = xrandom() >> 16;
			in[b] = x;
			xt += aescycles(); xt += aescycles(); xt += aescycles();
			xt += aescycles(); xt += aescycles();
		}
		if( xt > bestxt )
			bestx = x, bestxt = xt;
	}
	return bestx;
}

void bernstein (char *seed)
{
int loops, b, j, k;

	mrandom (strlen(seed), seed);

	for( loops = 4; loops <= 65536; loops *= 16) {
		for( b = 0; b < 16; b++ ) {
			printf ("%.2d, %.5d loops:", b, loops);
			for( k = 0; k < 10; k++ ) {
				for( j = 0; j < 16; j++ )
					key[j] = xrandom() >> 16;
				aes_expkey (key, expkey);
				printf (" %.2x", bestx (b, loops) ^ key[b]);
				fflush (stdout);
			}
			printf ("\n");
		}
	}
}
#endif

void prt_tables ()
{
uchar c0, c1, c2, c3;
int i = 0;
int ch;

	while( i < 256 ) {
		ch = U0[i++];
		c0 = ch >> 24;
		c1 = ch >> 16;
		c2 = ch >> 8;
		c3 = ch;
		printf("V(%.2x,", c0);
		printf("%.2x,", c1);
		printf("%.2x,", c2);
		printf("%.2x)\n", c3);
	}
}

int main (int argc, char *argv[])
{
#ifndef unix
extern int __cdecl _setmode (int, int);

	_setmode (_fileno(stdout), _O_BINARY);
#endif

	switch( argv[1][0] ) {
	case 'c': certify(); break;
	case 'e': encrypt(argv[2], argv[3]); break;
	case 'd': decrypt(argv[2], argv[3]); break;
	case 't': prt_tables(); break;
#ifndef unix
	case 'b': bernstein(argv[2]);	break;
#endif
	}
}

/*
 * The package generates far better random numbers than a linear
 * congruential generator.  The random number generation technique
 * is a linear feedback shift register approach.  In this approach,
 * the least significant bit of all the numbers in the RandTbl table
 * will act as a linear feedback shift register, and will have period
 * of approximately 2^96 - 1.
 *
 */

#define RAND_order (7 * sizeof(unsigned))
#define RAND_size (96 * sizeof(unsigned))

uchar RandTbl[RAND_size + RAND_order];
int RandHead = 0;

/*
 * random: 	x**96 + x**7 + x**6 + x**4 + x**3 + x**2 + 1
 *
 * The basic operation is to add to the number at the head index
 * the XOR sum of the lower order terms in the polynomial.
 * Then the index is advanced to the next location cyclically
 * in the table.  The value returned is the sum generated.
 *
 */

unsigned xrandom ()
{
register unsigned fact;

	if( (RandHead -= sizeof(unsigned)) < 0 ) {
		RandHead = RAND_size - sizeof(unsigned);
		memcpy (RandTbl + RAND_size, RandTbl, RAND_order);
	}

	fact = *(unsigned *)(RandTbl + RandHead + 7 * sizeof(unsigned));
	fact ^= *(unsigned *)(RandTbl + RandHead + 6 * sizeof(unsigned));
	fact ^= *(unsigned *)(RandTbl + RandHead + 4 * sizeof(unsigned));
	fact ^= *(unsigned *)(RandTbl + RandHead + 3 * sizeof(unsigned));
	fact ^= *(unsigned *)(RandTbl + RandHead + 2 * sizeof(unsigned));
	return *(unsigned *)(RandTbl + RandHead) += fact;
}

/*
 * mrandom:
 * 		Initialize the random number generator based on the given seed.
 *
 */

void mrandom (int len, char *ptr)
{
unsigned short rand = *ptr;
int idx, bit = len * 4;

	memset (RandTbl, 0, sizeof(RandTbl));
	RandHead = 0;

	while( rand *= 20077, rand += 11, bit-- )
		if( ptr[bit >> 2] & (1 << (bit & 3)) )
			for (idx = 0; idx < 5; idx++) {
				rand *= 20077, rand += 11;
				RandTbl[rand % 96 << 2] ^= 1;
			}

	for( idx = 0; idx < 96 * 63; idx++ )
		xrandom ();
}
#endif

