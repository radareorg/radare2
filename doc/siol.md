SIOL - Simple IO Layer
======================

Top-Down-View of siol
---------------------

	+==================+
	| Write-Mask       |
	+==================+
	| Buffer           | <--- maybe this could be deprecated, I see no usecase for the buffer
	+==================+
	| Cache (V)        |
	+==================+      +========================+
	| Maps             | <=== | Sections (transformed) |
	+==================+      +========================+
	| Descs            |
	|      +===========+
	|      | Cache (P) |
	+======+===========+
	| Plugin           |
	+==================+

Maps
----

every map has a mapid which is a unique identifier. Code from the outside of RIO shall use this id instead of a pointer. This may cost performance, but pointers can hurt you.

Mapping information in the map:

- from
- to
- delta
- fd

Section Transformation
----------------------
atm there are 3 different transformation-targets:

- Hexeditor
- Analysis
- Emulation

Mapping information in the section:

- addr
- size
- vaddr
- vsize
- fd

A section can be related to 2 maps:

- memmap
- filemap

Hexeditor-Transformation:

- check if addr != vaddr, if so continue
- create a map with the size of min (size, vsize), that maps the to fd corresponding desc to vaddr, starting at addr
- filemap is set to the id of the map
- memmap stays 0

Analysis-Transformation:

- when vsize <= size perform Hexeditor-Transformation, and you're done
- create a map with the size of size, that the to fd corresponding vaddr, starting at addr
- filemap is set to the id of the map
- open a new desc, using the null-plugin, with the size of vsize - size
- create another map with the size of vsize - size, that maps the new desc to vaddr + size, starting at 0x0
- memmap is set to the id of the second map

Emulation-Transformation:

- when the section does not allow write-access perform Analysis-Transformation, and you're done
- open a new desc with write-permissions, using the malloc-plugin, with the size of vsize
- copy min (size, vsize) bytes fram the desc, that fd refers to, starting at addr, to the new desc, starting at 0x0
- create a map with the size of vsize, that maps the new desc to vaddr, starting at 0x0
