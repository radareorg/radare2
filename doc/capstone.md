Capstone
========

Capstone Engine is the disassembler engine used by radare2 by default for 
some architectures.

Radare2 ships its own version of capstone based on the -next branch with
some minor patches. The problem is that latest release have some compile
time dependencies that make compilation with older releases a bit harder.

In order to build r2 against capstone3 you can do the following things:

	$ cd shlr
	$ rm -rf capstone
	$ make capstone-sync CS_RELEASE=1
	$ make -j4

If you are a distro packager it will be necessary to fix the include path
in the package script like this:

	$ ln -fs /usr/include libr/include/capstone

This is because capstone3 pkg-config file references the files directly
inside the /usr/include/capstone directory. so the includes in code must
be like this:

	#include <capstone.h>
	#include <arm.h>

This was fixed in capstone4 that will be released later this year, but as
long as distros will take some time to upgrade it is good to provide a
clean workaround to support both without having to change all the C files

	#include <capstone/capstone.h>
	#include <capstone/arm.h>
