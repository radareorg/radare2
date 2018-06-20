FLIRT
=====

At the  moment of  writing r2  supports  loading  and finding  FLIRT
patterns, those files can be generated with the FLIRT tools from IDA.
R2 doesn't  yet supports creating  those files.  But it supports its
own signature format  which can be used  to generate signatures  and
find them.

This document will focus on FLIRT, not the native r2 'Zignatures'.

You need the flair tools/ida utilities. Those tools are closed source
and privative, so you should not distribute them. It is probable that
it is  not possible  to redistribute the  .pat or the .sig files.  It
doesn't  seems to  have watermarks.  However it's  a bit unclear  what
licence the file generated should have.  Mentioning the files should
be free of copyrighted material  (the original libs bytes). That said,
there's a paragraph in [IDA F.L.I.R.T. Technology: In-Depth](https://www.hex-rays.com/products/ida/tech/flirt/in_depth.shtml)


Create the .pat file
--------------------

	cd flair/bin/linux
	./pelf -p64 /usr/lib/x86_64-linux-gnu/libc.a libc.pat

Create the .sig file (possible collisions):
--------------------

	./sigmake -n <libname> libc.pat libc.sig

There's little chance libc.sig will  be compatible across systems and
libc versions. If libc.exc exists, you need to resolve some functions
conflicts.  Prepend a '+' on the lines  you're sure you  want to keep
(see end of flair/sigmake.txt).  Then redo the  sigmake command.  The
.sig is now ready to be used with r2.

Using it with r2:
-----------------

    r2 -c 'zF libc.sig' staticbin

refs:

* flair/sigmake.txt
* flair/pat.txt

