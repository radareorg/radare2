ORACLE SOLARIS NOTES
====================

Packages you need:
------------------
```
pkg install gcc-3 gmake
```

To compile it:
--------------
```
./configure --disable-debugger --without-gmp
gmake
gmake install
```
