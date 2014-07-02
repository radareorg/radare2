SDB (string database)
=====================

sdb is a simple string key/value database based on djb's cdb
disk storage and supports JSON and arrays introspection.

mcsdbd is a memcache server with disk storage based on sdb.
It is distributed as a standalone binary and a library.

There's also the sdbtypes: a vala library that implements
several data structures on top of an sdb or a memcache instance.

[![Build Status](http://ci.rada.re/buildStatus/icon?job=sdb)](http://ci.rada.re/job/sdb/)

[![Build Status](https://scan.coverity.com/projects/1651/badge.svg)](https://scan.coverity.com/projects/1651)

Author
------
pancake <pancake@nopcode.org>

Contains
--------
* namespaces (multiple sdb paths)
* atomic database sync (never corrupted)
* bindings for vala, luvit, newlisp and nodejs
* commandline frontend for sdb databases
* memcache client and server with sdb backend
* arrays support (syntax sugar)
* json parser/getter (js0n.c)

Rips
----
* disk storage based on cdb code
* memory hashtable based on wayland code
* linked lists from r2 api

Changes
-------
I have modified cdb code a little to create smaller databases and
be memory leak free in order to use it from a library.

The sdb's cdb database format is 10% smaller than the original
one. This is because keylen and valuelen are encoded in 4 bytes:
1 for the key length and 3 for the value length.

In a test case, a 4.3MB cdb database takes only 3.9MB after this
file format change.

Usage example
-------------
Let's create a database!

	$ sdb d hello=world
	$ sdb d hello
	world

Using arrays (>=0.6):

	$ sdb - '[]list=1,2' '[0]list' '[0]list=foo' '[]list' '[+1]list=bar'
	1
	foo
	2

Let's play with json:

	$ sdb d g='{"foo":1,"bar":{"cow":3}}'
	$ sdb d g:bar.cow
	3
	$ sdb - user='{"id":123}' user:id=99 user:id
	99

Using the commandline without any disk database:

	$ sdb - foo=bar foo a=3 +a -a
	bar
	4
	3

	$ sdb -
	foo=bar
	foo
	bar
	a=3
	+a
	4
	-a
	3
	
Remove the database

	$ rm -f d
