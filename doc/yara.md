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

Yara in radare2
----------

radare2 provides several commands, allowing the user, to add or remove rules,
scan a file, and list or use rules tags.

You can list the yara commands with the following r2 command `yara [help]`.

Example
-------

Load a rule file on the fly, and then scan the currently opened file:

	yara add /home/name/rules/malware.rules
	yara scan
