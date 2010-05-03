Signatures
==========
Signatures are byte streams used to identify functions, strings
or watermarks inside binaries.

They are mostly helpful when working with static binaries and
it is used to identify which functions from which libraries
has been compiled into the static bin.

But there are other reasons to use them, like finding unreachable
code, get name of unknown functions, etc..

Byte-based signatures
---------------------

Those byte streams are used in the most basic signature checking
algorithm. They have:

* byte array
* binary mask
* size of blob

The binary mask is required to ignore all those variable bits used
to point data by the target code. The code analysis module can do
this job for you.

Example code:

	_foo:              ; dummy label
	mov eax, 33        ; reg, const
	push ebx           ; reg
	push [0x8049400]   ; absolute address (ignored by signature)
	call 0x80434830    ; absolute address call (ignored by sign)
	cmp eax, 0         ; reg, const
	jz _foo            ; relative address (used by the signature)

Other kind of signatures
------------------------

There are other types of ways to identify functions inside a binary,
here's a small list of them:

* function preludes

	By understanding that most of the functions will be
	prefixed with some standard bytes to construct the
	stack frame and store return address on stack (depending
	on compiler and architecture)

* code analysis

	Code analysis can be used to determine other characteristics of a
	function like number of basic blocks, code and data references, etc..

* callgraph

	The name of the function can be determined by identifying
	the functions called from the target one.

	This metric can be used to generate an automated function
	name if unknown or use it as a signature to collect this
	name from the loaded signature database.

Inline functions
----------------

The compilers usually inline some small functions inside other
functions. The size restriction is because the CPU cache that
can make the program run slower than using a 'call'.

As they are small and they can va
Those kind of functions are not going to be covered by this
method because of the complexity and the small signature they
