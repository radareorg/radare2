/*
Copyright (c) 2014, Colin Childs <colin@insecure-complexity.ca>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.

    * Neither the names of the copyright owners nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

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
*/

rule BLOWFISH_Constants : crypto {
        meta:
                author = "phoul (@phoul)"
                description = "Look for Blowfish constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { D1310BA6 }
		$c1 = { A60B31D1 }	
		$c2 = { 98DFB5AC }
		$c3 = { ACB5DF98 }
		$c4 = { 2FFD72DB }
		$c5 = { DB72FD2F }
		$c6 = { D01ADFB7 }
		$c7 = { B7DF1AD0 }
		$c8 = { 4B7A70E9 }
		$c9 = { E9707A4B }
		$c10 = { F64C261C }
		$c11 = { 1C264CF6 }
	condition:
                6 of them
}
rule MD5_Constants : crypto {
        meta:
                author = "phoul (@phoul)"
                description = "Look for MD5 constants"
                date = "2014-01"
                version = "0.2"
        strings:
		// Init constants
		$c0 = { 67452301 }
		$c1 = { efcdab89 }
		$c2 = { 98badcfe }
		$c3 = { 10325476 }
		$c4 = { 01234567 }
		$c5 = { 89ABCDEF }
		$c6 = { FEDCBA98 }
		$c7 = { 76543210 }	
		// Round 2
		$c8 = { F4D50d87 }
		$c9 = { 78A46AD7 }
	condition:
                5 of them
}
rule RC6_Constants : crypto {
        meta:
                author = "chort (@chort0)"
                description = "Look for RC6 magic constants in binary"
                reference = "https://twitter.com/mikko/status/417620511397400576"
                reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
                date = "2013-12"
                version = "0.2"
        strings:
                $c1 = { B7E15163 }
                $c2 = { 9E3779B9 }
                $c3 = { 6351E1B7 }
                $c4 = { B979379E }
        condition:
                2 of them
}rule RIPEMD160_Constants : crypto {
        meta:
                author = "phoul (@phoul)"
                description = "Look for RIPEMD-160 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
		5 of them
}
rule SHA1_Constants : crypto {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA1 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
                5 of them
}
rule SHA256_Constants : crypto {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA224/SHA256 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		// Exclude
		$e0 = { D728AE22 }
		$e1 = { 22AE28D7 }
	condition:
                4 of ($c0,$c1,$c2,$c3,$c4,$c5,$c6,$c7) and not ($e0 or $e1)
}
rule SHA512_Constants : crypto {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA384/SHA512 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		$c8 = { D728AE22 }
		$c9 = { 22AE28D7 }
	condition:
		5 of them
}
rule WHIRLPOOL_Constants : crypto {
        meta:
                author = "phoul (@phoul)"
                description = "Look for WhirlPool constants"
                date = "2014-02"
                version = "0.1"
        strings:
		$c0 = { 18186018c07830d8 }
		$c1 = { d83078c018601818 }
		$c2 = { 23238c2305af4626 }
		$c3 = { 2646af05238c2323 }
	condition:
                2 of them
}
