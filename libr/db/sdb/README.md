SDB (simple database)
=====================
author: pancake

Description
-----------
sdb is a simple key/value database with disk storage.
mcsdbd is a memcache server with disk storage based on sdb.
sdbtypes is a vala library that implements several data
structures on top of an sdb or memcache instance.

json is supported in the core api. You can store json
objects as value for a specific key and access the members
using a path expression (get and set).

namespace are also supported using the sdb_ns api, which
permits to store various references to other Sdb instances
from a single one.

Contains
--------
* vala, luvit, newlisp and nodejs bindings
* commandline frontend for sdb databases
* memcache client and server with sdb backend
* json parser/getter (js0n.c)

Rips
----
* disk storage based on cdb code
* memory hashtable based on wayland code
* linked lists from r2 api

Changes
-------
I have slightly modified the cdb code to get smaller databases
and be memory leak free.

The sdb's cdb database format is 10% smaller than the original
one. This is because keylen and valuelen are encoded in 4 bytes:
1 for the key length and 3 for the value length.

In a test case, a 4.3MB cdb database takes only 3.9MB after this
file format change.

Example
-------
Let's create a database!

	$ sdb d hello=world
	$ sdb d hello
	world

Let's play with json:

	$ sdb d g='{"foo":1,"bar":{"cow":3}}'
	$ sdb d g?bar.cow
	3
	$ sdb - user='{"id":123}' +user?id user?id
	123
	124

Use the prompt:

	$ sdb -
	foo=bar
	foo
	bar
	a=3
	+a
	3
	a
	4
	-a
	4
	
Remove the database

	$ rm -f d # :)

Backups
-------
To make a backup of a database to move it between different boxes use the textual format:

	$ sdb my.db | xz > my.xz
	$ du -hs my.*
	my.db        3.9M
	my.xz        5K

Using ascii+xz is the best option for storing compressed sdb databases:

	$ gzip < my.db | wc -c
	  110768
	$ xz -9 < my.db | wc -c
	  37480
	$ sdb my.db | xz -9 | wc -c
	  5620
	$ sdb my.db | lzma -9 | wc -c
	  5575

To import the database:

	$ xz -d < my.xz | sdb my.db =
