spp
===

Author: pancake <pancake<at>nopcode<dot>org>
License: MIT

Description
-----------
SPP stands for Simple Pre-Processor.

The primary use of spp is as a templating language, with
similarities to PHP and CPP. Allowing to embed scripts
in any language in some specific places of the document.

Configuration
-------------
SPP binary can be configured by changing the values in the config.h file, this way you can specify which preprocessors you want to include in the parser.

	# Edit the config.h file before typing 'make'

See config.def.h as an example

Build
-----
	$ make

Installation
------------

	$ make install PREFIX=/usr

Embedding
---------

There are no embedding issues with the MIT license and the
amount if code is pretty low (~400 LOC), and use the apis:

	struct Proc p = {0};
	spp_proc_set (&p, "sh", 99);
	char *res = spp_eval(&p, "hello {{echo orld}}"
	printf ("(%s)\n", res);
