TODO: Move this document into the book when ready

Syncing
=======

The ability to work collaboratively is an important problem
to solve when working with big binaries, when the time is
a restriction, or even when teaching.

Radare2 have been shipping since the very beginning an
embedded webserver and a rap server that allows to expose
the current sesson to the network, but syncing requires a
bunch of extra processes to make it work.

The following sections describe the easiest way to share
a session with another user and allow them to interact get
real-time updates of the changes happening in the running
session.

Listening for clients
---------------------

The concepts of client and server in r2land a bit blurry
because it can do both, and you can create a distributed
network of r2 nodes connected between them without a central
authority.

For simplicity we will use the http webserver which can be
launched with the `=h` command, use `=h&` if you want to
run that in background.

Security
--------

This behaviour exposes a clear security risk, and it must
be taken in account in order to avoid surprises. Right
now r2 doesn't have http auth or ssl pinning, so you may
restrict the clients by IP.

The problem of 
