Licensing
=========

Before you try to statically link r2, you should know about the licenses that go along with it, 

http://stackoverflow.com/questions/10130143/gpl-lgpl-and-static-linking

Also this stackoverflow page explains the legal case of using it via r2pipe,

http://stackoverflow.com/questions/1394623/can-i-dynamically-call-a-lgpl-gpl-software-in-my-closed-source-application

LGPLv3 keeps the freedom to the user to switch to a different version of the r2 libraries, so static linking is not permitted unless the privative software is distributed with the object files needed to do the full static link, so the users will be able to upgrade or modify r2 libraries even if 

r2 is licensed under the LGPL license, which permits statically linking, but forces you to liberate the object files and a way to allow users to link them.

r2pipe or scripting/plugins can be used from r2 without any kind of legal issue, only if you modify r2 to make it work with your tools, you should make those changes public, this way we ensure the users always have the freedom to change or upgrade the r2 libraries that come along with r2.

Some parts of r2 are under the GPL license, here's a list of them:

* C++ demangler (libr/bin)
* Some exotic disassemblers
* GNU binutils disassemblers (libr/asm)
* GRUB filesystems (libr/fs)

If you are going to use r2 in your propietary product bear in mind to build it without those parts, which may infect your program. Please refer to the FSF or GNU sites to understand how licenses work.

As long as r2pipe, or webui access is done via a textual interface which requires no reverse engineering or linking for integration other programs will not be affected by the license rules.

If you have any other question about how to use, build, link and distribute r2 with your own tools drop me an email (pancake@nopcode.org) or just talk to the Free Software Foundation in order to clarify that.

--pancake
