Trying to escape from the libr/core mess, we should put all the heap stuff into a separate place and use it from anal/heap.c

TODO

* remove all use of assert
* remove unused statements
* convert macros into C code, this should be a runtime library, not a compile time one
