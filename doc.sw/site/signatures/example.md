Using signatures in radare
==========================

All the actions related to signatures in radare2 are collected
in the 'z' command.

Here is the command help:

	[0x000018a0]> z?
	Usage: z[abcp/*-] [arg]
	 z              show status of zignatures
	 z*             display all zignatures
	 zp             display current prefix
	 zp prefix      define prefix for following zignatures
	 zp-            unset prefix
	 z-prefix       unload zignatures prefixed as
	 z-*            unload all zignatures
	 za ...         define new zignature for analysis
	 zb name bytes  define new zignature for bytes
	 zf name bytes  define new function prelude zignature
	 zg pfx [file]  generate siganture for current file
	 .zc @ fcn.foo  flag signature if matching (.zc@@fcn)
	 z/ [ini] [end] search zignatures between these regions
	NOTE: bytes can contain '.' (dots) to specify a binary mask


