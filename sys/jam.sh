#!/bin/sh

# shellcheck disable=SC2046
rm -rf $(find ./*| grep bin/darwin)
cd shlr
for a in ./* ; do
 if [ -e "$a/Jamroot" ]; then
   cd "$a" || exit 1
   bjam -j4
   cd ..
 fi
done
cd ../libr
for a in ./* ; do
 if [ -e "$a/Jamroot" ]; then
   cd "$a" || exit 1
   bjam -j4
   cd ..
 fi
done

cd ..
cd binr
for a in ./* ; do
 if [ -e "$a/Jamroot" ]; then
   cd "$a" || exit 1
   bjam -j4
   cd ..
 fi
done
