#!/bin/sh
if [ "$1" = "-h" ]; then
cat <<EOF
Usage:

Clone and inspect latest commits:

  git clone https://github.com/rizinorg/rizin
  cd rizin
  git format-patch -100
  vim . # press p over the file name to preview the patch

In another terminal in the root of r2:

  sys/derizin.sh < rizin/0032* > p;git am --abort; git am -3 p

If the above command fails do it manually:

  patch -p1 < p

And create the fake commit like this:

  AUTHOR="`grep p ^From:|cut -d : -f 2-`"
  git commit --author "$AUTHOR" -a

Be careful with new files, you will need to add them with

  git add missing-file.c

PD: Open the 'p' file in a split in vim to copypaste the
commit message from the subject of the formatted patch.
EOF
exit 0
fi


sed \
 -e 's,_ANALYSIS_,_ANAL_,g' \
 -e 's,RAnalysis,RAnal,g' \
 -e 's,RZ_,R_,g' \
 -e 's,rz_,r_,g' \
 -e 's,rz-test,r2r,g' \
 -e 's,tools/r_bin,tools/rabin2,g' \
 -e 's,analysis,anal,g' \
 -e 's,librz,libr,g' \
 -e 's,binrz,binr,g' \
 -e 's,rizin,radare2,g' \
 -e 's,Rz,R,g'
