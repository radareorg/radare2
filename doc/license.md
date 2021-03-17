# Licensing

Before you try to statically link r2, you should know about the licenses that go along with it, 

http://stackoverflow.com/questions/10130143/gpl-lgpl-and-static-linking

Also this stackoverflow page explains the legal case of using it via r2pipe,

http://stackoverflow.com/questions/1394623/can-i-dynamically-call-a-lgpl-gpl-software-in-my-closed-source-application

LGPLv3 keeps the freedom to the user to switch to a different version of the r2 libraries, so static linking is not permitted unless the privative software is distributed with the object files needed to do the full static link, so the users will be able to upgrade or modify r2 libraries even if 

r2 is licensed under the LGPL license, which permits statically linking, but forces you to liberate the object files and a way to allow users to link them.

r2pipe or scripting/plugins can be used from r2 without any kind of legal issue, only if you modify r2 to make it work with your tools, you should make those changes public, this way we ensure the users always have the freedom to change or upgrade the r2 libraries that come along with r2.

If you are going to use r2 in your proprietary product bear in mind to build it without those parts, which may infect your program. Please refer to the FSF or GNU sites to understand how licenses work.

As long as r2pipe, or webui access is done via a textual interface which requires no reverse engineering or linking for integration other programs will not be affected by the license rules.

If you have any other question about how to use, build, link and distribute r2 with your own tools drop me an email (pancake@nopcode.org) or just talk to the Free Software Foundation in order to clarify that.

## Plugins license

The radare2 plugins expose the licensing information in the definition structure:

```c
RAsmPlugin r_asm_plugin_dummy = {
  ...
  .license = "LGPL3",
  ...
};
```

This information is accessible at runtime by using the `L` command or commandline flag in any of the r2 programs:

```
$ r2 -Lj | jq -r '.[].license' | sort -u
BSD
GPL3
LGPL
LGPL3
MIT
```

## WebUI license

Please refer to the radare2-webui repository for a detailed list of all the javascript frameworks used on every webui shipped under the shlr/www directory. Read the following links for detailed understanding of licensing the web.

* https://www.gnu.org/software/librejs/free-your-javascript.html
* http://greendrake.info/#nfy0

## Non-LGPL code shipped in r2

Some parts of r2 are not under the LGPL license, this is a list of them sorted 

### GPL: More restrictive than LGPL

The plugins written under the GPL license can be opt-out at compile time in case you are worried about them.

Using the acr/make build system:

```
$ ./configure --without-gpl
```

Using the meson build system:

```
$ meson -D nogpl=true
```

Note that by default both build systems will behave the same way if no options are passed.

You can get a list of safe non-gpl plugins in the `dist/plugins-cfg/plugins.nogpl.cfg` which
should be copied to `./plugins.cfg` before calling `./configure-plugins` to take effect.

### Less restrictive than LGPL

* libr/asm/arch/gnu: GPLv2
* libr/bin/mangling/cxx: GPLv2
* shlr/capstone: BSD + LLVM
* shlr/zip/zip: BSD
* shlr/zip/zlib: BSD
* shlr/java: Apache2.0
* shlr/sdb: MIT
* shlr/qnx: GPL (will be moved to extras soon)
* shlr/grub: GPL (used by some fs plugins)
* shlr/yxml: BSD
* shlr/lz4: simplified BSD license
* shlr/mpc: BSD3

### The rest of code in shlr/ follows the LGPL

* shlr/winkd: LGPL
* shlr/bochs: LGPL
* shlr/tcc: LGPL
* shlr/spp: LGPL (may change to MIT or BSD)
* shlr/gdb: LGPL

--pancake
