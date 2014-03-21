#!/bin/sh
D=`dirname $PWD/$0`
uncrustify -c ${D}/uncrustify.cfg $@
diff -ru $1 $1.uncrustify
