#!/bin/sh
sys/meson.py || exit 1
(
	cd build || exit 1
	rm -rf a
	mkdir a
	for a in `find *| grep '\.a$'` ; do
		echo $a
		b=`basename $a`
		mkdir a/$b
		(cd a/$b ; ar xv ../../$a) > /dev/null
	done
	(
		rm -f libr.a
		cd a
		ar crs ../libr.a */*.o
	)
)
D=r2sdk
rm -rf $D
mkdir -p $D/lib || exit 1
cp -rf libr/include $D
cp -f build/libr.a $D/lib
rm -f $D.zip
zip -r $D.zip $D > /dev/null

cat > .test.c <<EOF
#include <r_core.h>
int main() {
	RCore *core = r_core_new ();
	r_core_free (core);
}
EOF
gcc .test.c -I $D/include $D/lib/libr.a
