Flags
=====

Flags are used to specify bookmarks inside radare, they are store the following data:

* name
* offset
* size
* flagspace

The command 'f' is responsible to manage the flag list.

	> fs imports       # select flagspace 'imports'
	> f                # list flags
	> f *              # list all flags in radare commands
	> fs *             # select no flagspace
	> f target @ 10    # create/set flag 'target' at offset 10
	> f-target         # remove flag named 'target'

Sorting flags
-------------

r2 have a new command named 'fS' which is used to sort flags by name (fSn) or offset (fSo).

In 'Vt' you can sort the flags using 'o' and 'n' keys.

	> f alice @ 0x20
	> f bob @ 0x10
	> fSn
	> f
	0x00000020 0 alice
	0x00000010 0 bob
	> fSo
	> f
	0x00000010 0 bob
	0x00000020 0 alice


Visual mode
-----------

Vt command from shell will emulate typing 't' in 'V'isual mode, so you get the same menu which allows you list, add and remove flags and flagspaces.

Press '?' to get help of keybindings.

	> Vt

	 Flag spaces:

	   00   sections
	   01 * symbols
	 > 02   imports
	   03   functions
	   04   *

	<enter>
	
	 Flags in flagspace 'imports'. Press '?' for help.

	 >  000 0x080496f4    0 imp.malloc
	    001 0x080494b4    0 imp.free
	    002 0x08049884    0 imp.cap_get_file
	    003 0x08049874    0 imp.exit
	    ...

	 Selected: imp.malloc

	 ||||   0x080496f4  *[ fcn.imp.malloc]  jmp dword near [0x805e82c]
	 ||||   0x080496fa          6828020000  push dword 0x228
	 |||`=< 0x080496ff          e990fbffff  jmp section..plt

