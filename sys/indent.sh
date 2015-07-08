#!/bin/sh
D="$(dirname "$PWD/$0")"
#shellcheck disable=SC2048
#shellcheck disable=SC2086
uncrustify -c ${D}/uncrustify.cfg $*
diff -ru "$1" "$1.uncrustify"
