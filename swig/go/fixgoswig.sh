#!/bin/sh
# fixgoswig.sh - Fix ut64 consts and convert std::vector into slice

FILE=$1
sed -n '
1h
1!H
$ {
	g
	s/\(\n\t[^\n(]*([^\n)]*)\) \([a-zA-Z0-9]\+\)Vector/\1 []\2/g
	s/\(\nfunc ([^\n]*\) \([a-zA-Z0-9]\+\)Vector {\n\treturn \([^\n]*\)\n}/\1 []\2 {\
	v := \3\
	n := v.Size()\
	if n  <= 0 {\
		return nil\
	}\
	s := make([]\2, n)\
	for i := 0; i < n; i++ {\
		it := v.Get(i)\
		s[i]=it;\
	}\
	return s\
}/g
	p
}
' $FILE > $FILE.fix
mv -f $FILE.fix $FILE
