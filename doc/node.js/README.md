Node.JS express based webserver
===============================

Author : pancake <pancake@nopcode.org>

Date: 2015-03-31

Description
-----------

This is the nodejs implementation of a websever
for radare2. This script can be executed from
inside r2 by using the following commnad:

	> #!pipe node .

If you don't have any other .js handler (like duktape)
you can run it directly like this:

	$ . index.js

From the shell you can run the script like this:

	$ r2 -c '#!pipe node index.js' /bin/ls

Or just run it from nodejs:

	$ node .

Or specify a different file to open

	$ node . /bin/awk
