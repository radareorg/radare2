Yara plugin
===========

Preliminary documentation on yara can be found here:
[Yara User's Manual](https://b161268c3bf5a87bc67309e7c870820f5f39f672.googledrive.com/host/0BznOMqZ9f3VUek8yN3VvSGdhRFU/YARA-Manual.pdf)

The following is 'YARA in a nutshell' from this document:

> YARA is a tool aimed at helping malware researchers to identify and classify malware
families. With YARA you can create descriptions of malware families based on textual or
binary information contained on samples of those families. These descriptions, a.k.a rules,
consist patterns and a boolean expression which determines its
logic. Rules can be
applied to files or running processes in order to determine if it belongs to the described
malware family.

Requirements
------------

You can either install libyara with your prefered package manager, or you
can execute `r2pm -i yara3-lib` and `r2pm -i yara3` in order to retrieve
latest source, compile, and install the library.

Yara in radare2
----------

radare2 provides several commands, allowing the user, to add or remove rules,
scan a file, and list or use rules tags.

You can list the yara commands with the following r2 command `yara3 [help]`.

Rules
-----

By default, radare2 ships with some common crypto and packers rules that you
can find in `/usr/local/share/radare2/last/yara/` if you installed it r2 or
`radare2/shlr/yara/` in the git repo.
They are loaded as soon as you start using the yara plugin.
So you can issue `yara scan` and automatically see if your binary is packed
with a known packer.

Example
-------

Load a rule file on the fly, and then scan the currently opened file:
```
yara3 add /home/name/rules/malware.rules
yara3 scan
```
Yara versions
-------------

Because radare2 has support for both yara versions currently,
depending from the version/plugin you've loaded, you need
to use the proper versioned command.
E.g. `yara2` or `yara3`. For example `yara3 scan`.
