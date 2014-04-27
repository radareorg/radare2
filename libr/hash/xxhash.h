/*
   xxHash - Fast Hash algorithm
   Header File
   Copyright (C) 2012, Yann Collet.
   BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met:
  
       * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
       * Redistributions in binary form must reproduce the above
   copyright notice, this list of conditions and the following disclaimer
   in the documentation and/or other materials provided with the
   distribution.
  
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	You can contact the author at :
	- xxHash source repository : http://code.google.com/p/xxhash/
*/

/* Notice extracted from xxHash homepage :

xxHash is an extremely fast Hash algorithm, running at RAM speed limits.
It also successfully passes all tests from the SMHasher suite.

Comparison (single thread, Windows Seven 32 bits, using SMHasher on a Core 2 Duo @3GHz)

Name            Speed       Q.Score   Author
xxHash          5.4 GB/s     10
CrapWow         3.2 GB/s      2       Andrew
MumurHash 3a    2.7 GB/s     10       Austin Appleby
SpookyHash      2.0 GB/s     10       Bob Jenkins
SBox            1.4 GB/s      9       Bret Mulvey
Lookup3         1.2 GB/s      9       Bob Jenkins
SuperFastHash   1.2 GB/s      1       Paul Hsieh
CityHash64      1.05 GB/s    10       Pike & Alakuijala
FNV             0.55 GB/s     5       Fowler, Noll, Vo
CRC32           0.43 GB/s     9
MD5-32          0.33 GB/s    10       Ronald L. Rivest
SHA1-32         0.28 GB/s    10

Q.Score is a measure of quality of the hash function. 
It depends on successfully passing SMHasher test set. 
10 is a perfect score.
*/

#pragma once

#if defined (__cplusplus)
extern "C" {
#endif


//****************************
// Simple Hash Functions
//****************************

unsigned int XXH32 (const void* input, int len, unsigned int seed);

/*
XXH32() :
	Calculate the 32-bits hash of "input", of length "len"
	"seed" can be used to alter the result
	This function successfully passes all SMHasher tests.
	Speed on Core 2 Duo @ 3 GHz (single thread, SMHasher benchmark) : 5.4 GB/s
	Note that "len" is type "int", which means it is limited to 2^31-1.
	If your data is larger, use the advanced functions below.
*/



//****************************
// Advanced Hash Functions
//****************************

void*        XXH32_init   (unsigned int seed);
int          XXH32_feed   (void* state, const void* input, int len);
unsigned int XXH32_result (void* state);

/*
These functions calculate the xxhash of an input provided in several small packets,
as opposed to an input provided as a single block.

You must start with :
void* XXH32_init()
The function returns a pointer which holds the state of calculation.

This pointer must be provided as "void* state" parameter for XXH32_feed().
XXH32_feed() can be called as many times as necessary.
The function returns an error code, with 0 meaning OK, and all other values meaning there is an error.
Note that "len" is type "int", which means it is limited to 2^31-1. 
If your data is larger, it is recommended
to chunk your data into blocks of size 2^30 (1GB) to avoid any "int" overflow issue.

Finally, you can end the calculation anytime, by using XXH32_result().
This function returns the final 32-bits hash.
You must provide the same "void* state" parameter created by XXH32_init().

Memory will be freed by XXH32_result().
*/


unsigned int XXH32_getIntermediateResult (void* state);
/*
This function does the same as XXH32_result(), generating a 32-bit hash,
but preserve memory context.
This way, it becomes possible to generate intermediate hashes, and then continue feeding data with XXH32_feed().
To free memory context, use XXH32_result().
*/



#if defined (__cplusplus)
}
#endif
