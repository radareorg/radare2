RAPATCH
=======

Human friendly text format to apply patches to binary files.


Patch format
------------

Those patches must be written in files and the syntax looks like the following:

^# -> comments
. -> execute command
! -> execute command
OFFSET { code block }
OFFSET "string"
OFFSET 01020304
OFFSET : assembly
+ {code}|"str"|0210|: asm

Example scripts
---------------
This script will run the '?e ..' command in r2 and then write the string 'Hello' at 0x200 offset

	# rapatch example
	:?e hello world
	0x200 "Hello"

Running rapatches
-----------------

	$ r2 -P rapatch.txt target-program.txt
