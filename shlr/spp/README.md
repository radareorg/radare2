spp
===

* **Author**: pancake (pancake@nopcode.org)
* **History**: 2009-2020
* **License**: MIT

Description
-----------
SPP stands for Simple Pre-Processor.

The primary use of spp is as a templating language, with
similarities to PHP and CPP. Allowing to embed scripts
in any language in some specific places of the document.

Build
-----

You can tweak some options with `./configure` (or copying your favourite `config.mk`)

```
Optional Features:
  --without-fork         build without depending on fork syscall
  --enable-r2            compile against r2 r_util
```

The way to build is as easy as in any GNU program:

```
$ ./configure --prefix=/usr
$ make
$ make install
```

Usage
=====

The `spp` program can be used like `cat`, but it will evaluate the
tokenized expressions specified by the preprocessors.

* Use `spp -l` to list the available preprocessors (default is `spp`)
* Use `spp -t cpp` to select the cpp preprocessor

Input can be stdin or all the files passed as argument.

```
$ echo 'Hello <{system uname}>' | spp
Hello Darwin
```

Embedding
---------

There are no embedding issues with the MIT license and the
amount if code is pretty low (~400 LOC), and use the apis:

```c
$ cat test.c
#include "spp.c"

int main() {
	char *p = spp_eval_str (&spp_proc, "Hello <{system uname}>");
	printf ("%s\n", p);
	free (p);
}

$ gcc test.c
$ ./a.out
Hello Darwin
```

Commandline
-----------

SPP is also a commandline tool that takes N files as arguments and
evaluates them using the selected preprocessor:

```
$ ./spp -h
Usage: ./spp [-othesv] [file] [...]
  -o [file]     set output file (stdout)
  -t [type]     define processor type (spp,cpp,pod,acr,sh)
  -e [str]      evaluate this string with the selected proc
  -s [str]      show this string before anything
  -l            list all built-in preprocessors
  -L            list keywords registered by the processor
  -n            do not read from stdin
  -v            show version information
spp specific flags:
 -I   add include directory
 -D   define value of variable
```

Preprocessors
=============

There are 5 preprocessors that are available in spp by default.
You can write your own and just pass the struct reference as
argument.

SPP
---

```xml
<{ set arch x86-32 }>

hello <{echo world}>
path=<{system echo $PATH}>
arch = <{ get arch }>

<{ ifeq arch x86-32 }>
FOO IS ENABLED
<{ endif }>
```

CPP
---

```c
#define FOO 1
#define MAX(x,y) (x>y)?x:y

main() {
	printf ("%d\n", MAX (3,10));
}
```

ASM
---

```asm
.include t/syscalls.asm
int3
```

...
