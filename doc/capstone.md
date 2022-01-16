Capstone
========

Capstone Engine is the disassembler engine used by radare2 by default for
some architectures.

R2 supports capstone 3, 4 and 5.

* capstone3: legacy support (only for Debian probably)
* capstone4: stable release at the moment of writing this
* capstone5: next branch, still under development (default)

By default r2 will build statically against capstone5 (unless you specify
the --with-capstone4 or --with-syscapstone configure flags)

Using system capstone
---------------------

You can link capstone dynamically (by using --with-syscapstone), this will skip all the
download and build steps of capstone inside `shlr/capstone`.and just link against the version
of capstone found in the system. That's what distros usually want.

NOTE: that building against capstone-master is cursedd, because cs-master reports v5, but code
is from v4, so it fails to compile because of missing enums and archs.

v4
--

To build r2 against capstone4 use the following oneliner:

	sys/install.sh --with-capstone4
