#!/bin/sh
PKG=org.radare.radare2
cd /

pkgutil --files ${PKG} > /dev/null || exit 1

# delete files
FILES=`pkgutil --only-files --files ${PKG}`
for a in ${FILES} ; do
if [ -f ${a} ]; then
 rm "$a"
 # | xargs rm -i
fi
done

# delete empty directories
FILES=`pkgutil --only-dirs --files ${PKG}`
for a in ${FILES} ; do
if [ -d ${a} ]; then
  rmdir "$a"
fi
done
pkgutil --forget ${PKG}
