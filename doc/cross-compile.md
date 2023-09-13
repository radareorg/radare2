So you want to cross-compile radare to some exotic architecture? Use docker and you'll save some headache:

https://github.com/dockcross/dockcross

Here's and example on how changes required for i.e ARMv5 (no hard float) borrowed from `mk/armel.mk`:

```bash
ARCH=arm
CROSS_ROOT=/usr/bin
CROSS_TRIPLET=${ARCH}-linux-gnueabi

CC=${CROSS_ROOT}/${CROSS_TRIPLET}-gcc
USERCC=${CROSS_ROOT}/${CROSS_TRIPLET}-gcc

RANLIB=${CROSS_TRIPLET}-ranlib
CC_AR=${CROSS_ROOT}/${CROSS_TRIPLET}-ar -r ${LIBAR}
(...)
```

After defining your new `mk/arch.mk` file it should be pretty straightforward to install the `dockcross`
tool from one of its own containers:

```
$ docker run thewtex/cross-compiler-linux-armv5 > ~/bin/dockcross
$ chmod +x ~/bin/dockcross
```

And then, compile normally from inside the container:

```
$ dockcross --image thewtex/cross-compiler-linux-armv5 ./configure --with-compiler=armel --host=armel
$ dockcross make
```

Here is some more context and references:

* https://github.com/radareorg/radare2/pull/5060
* https://blogs.nopcode.org/brainstorm/2016/07/26/cross-compiling-with-docker
