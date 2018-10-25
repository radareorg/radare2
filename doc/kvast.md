kvast
=====

KeyValue storage for AST

To optimize serialized storage use a concatenated
string array and use the sdb array string api

eax=33
------

	0.op=set     []0=set,eax,33
	0.a=eax
	0.b=33


ebx=(8*(eax+4))
---------------
	0.op=set     []0=set,ebx,$1
	0.a=ebx
	0.b=$1

	1.op=mul     []1=mul,8,$2
	1.a=8
	1.b=$2

	2.op=add     []2=add,eax,4
	2.a=eax
	2.b=4

ebx=8*(eax+4)+3
---------------
	0.op=set     []0=set,ebx,$3
	0.a=ebx
	0.b=$3

	1.op=mul     []1=mul,8,$2
	1.a=8
	1.b=$2

	2.op=add     []2=add,eax,4
	2.a=eax
	2.b=4

	3.op=add     []3=add,$1,3
	3.a=$1
	3.b=3

ebx=8*(eax+4+ecx+2)+1
---------------------
	0.op=set
	0.a=ebx
	0.b=$5

	1.op=mul
	1.a=8
	1.b=$4

(
	2.op=add
	2.a=eax
	2.b=4

// update toplevel b reference
	3.op=add
	3.a=$2
	3.b=ecx

// update toplevel b reference
	4.op=add
	4.a=$3
	4.b=2
}

// update toplevel b reference
	5.op=add
	5.a=$1
	5.b=1

Parsing
=======
Parsing is done by a state machine which reads the expression string and creates a keyvalue string that represents the ESIL instruction.

This is an example
```
	switch (ch) {
	case '+':
	case '-':
	case '*':
	case '/':
		if (expect_arg) {
			
			expect_arg = ch;
		}
		break;
	}
```
