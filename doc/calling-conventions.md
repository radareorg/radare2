Calling Conventions profiles
============================

Radare2 uses calling conventions to help in identifying function formal arguments and return types. It is used also as guide for basic function prototype (WIP at the time of writing this wiki).

Profile grammar
===============

Since the profiles are based on sdb database, Creating one is as simple as creating group of `key=value` pairs in text file. then parsing it into sdb data file.

Attribute list
==============

Note that you will substitute `x` for the calling convention name you will use.

`default.cc=x` : used to set the the default calling convention used for all functions in `RAnal` instance for which this key is set, string of this calling convention `"x"` will be returned for every call of `R_API const char *r_anal_cc_default(RAnal *anal)`.

`x=cc`: used to initialize calling convention (think of it as their is calling convention called x).

`cc.x.name=x`: This one is a bit awkward, it is used internally to improve memory usage by reducing memory consumption No need to worry about it except for calling convention profile will probably break if this one doesn't exist.

`cc.x.arg1=reg`, `cc.x.arg2=reg`: used to set the ith argument of this calling convention to register name, feel free to use whatever register name you want to as long as it is supported by the target architecture. Ex: `cc.optlink.arg1=eax` on x86 architecture.

`cc.x.argn=stack`: means that all the arguments (or the rest of them in case there was `argi` for any i as counting number) will be stored in stack from left to right. Ex `cc.cdecl.argn=stack`.

`cc.x.argn=stack_rev`: same as `cc.x.argn=stack` except for it means argument are passed right to left. Ex: `cc.stdcall.argn=stack_rev`

`cc.x.ret=reg`: used to set where the return value is stored for the given calling convention.

File Path
=========

In order to integrate the calling convention profile you created with the r2 source, few set of conventions should be followed:

- Store the unparsed sdb file in `path-to-radare2-source/libr/anal/d`.
- If you want the sdb to be loaded for specific architecture the file name should follow this convention `cc-arch-bits`, for example to create profile that loads automatically for x86 arch with 16 bits call the file `cc-x86-16`
- In the file `path-to-radare2-source/libr/anal/d/makefile` add entry `F+= cc-arch-bits` with desired arch and bits and you should be ready to go.


