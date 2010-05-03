r2 Hello World in python
========================

This snippet will open /bin/ls and disassemble 10 instructions at entrypoint:

	$ cat test.py
	from r2.libr import RCore
	c=RCore()
	c.file_open("/bin/ls", False)
	c.cmd0(".!rabin2 -re /bin/ls")
	print "Entrypoint: %s"%c.cmd_str("? entry0").split(" ")[1]
	print c.cmd_str("pd 10 @ entry0")


To run it:

	$ python test.py

	Entrypoint: 0x18a0

	  |   0x000018a0  *[         entry0]  xor ebp, ebp
	  |   0x000018a2                  5e  pop esi
	  |   0x000018a3                89e1  mov ecx, esp
	  |   0x000018a5              83e4f0  and esp, 0xf0
	  |   0x000018a8                  50  push eax
	  |   0x000018a9                  54  push esp
	  |   0x000018aa                  52  push edx
	  |   0x000018ab          68a0940508  push dword 0x80594a0
	  |   0x000018b0          68b0940508  push dword 0x80594b0
	  |   0x000018b5                  51  push ecx
	  |   0x000018b6                  56  push esi
	  |   0x000018b7          6840f80408  push dword 0x804f840
	  `=< 0x000018bc          e843fbffff  call 0x1404
