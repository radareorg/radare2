#!/bin/sh
#
# Copyright (C) 2011-2016  pancake <pancake@nopcode.org>
# Copyright (C) 2011-2012  Edd Barrett <vext01@gmail.com>
# Copyright (C) 2012       Simon Ruderich <simon@ruderich.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

lock() {
  while ! ln -s . lock 2>/dev/null ; do :; done
}

unlock() {
  rm -f lock
}

# Statistics.
TESTS_TOTAL=0
TESTS_SUCCESS=0
TESTS_FATAL=0
TESTS_FAILED=0
TESTS_BROKEN=0
TESTS_FIXED=0

# Let tests.sh know the complete test suite is run, enables statistics.
R2_SOURCED=1

control_c() {
  echo
  exit 1
}
trap control_c 2

if [ "$1" = "-j" ]; then
  shift
  THREADS=$1
  shift
else
  THREADS=8
fi

. ./tests.sh

radare2 -v
if [ $? != 0 ]; then
  echo "Cannot find radare2"
  exit 1
fi

NTH=0
TFS=""

[ "${THREADS}" -lt 1 ] && THREADS=1
[ -z "${THREADS}" ] && THREADS=8

FILE_SUCCESS=$(mktemp /tmp/.r2-stats.XXXXXX)
FILE_FAILED=$(mktemp /tmp/.r2-stats.XXXXXX)
FILE_FATAL=$(mktemp /tmp/.r2-stats.XXXXXX)
FILE_BROKEN=$(mktemp /tmp/.r2-stats.XXXXXX)
FILE_FIXED=$(mktemp /tmp/.r2-stats.XXXXXX)
FILE_TOTAL=$(mktemp /tmp/.r2-stats.XXXXXX)
FILES="${FILE_SUCCESS} ${FILE_FAILED} ${FILE_FIXED} ${FILE_BROKEN} ${FILE_TOTAL}"

for a in $FILES ; do
  echo 0 > $a
done

runfile() {
  [ -z "$2" ] && return
  if [ $THREADS -gt 0 ]; then
    TF=`mktemp /tmp/.r2-tests.XXXXXX`
    TFS="${TFS} $TF"
    NTH=$(($NTH+1))
    (
      cd $1 
      . ./$2 > $TF
      lock
      N=$((`cat ${FILE_SUCCESS}`+${TESTS_SUCCESS})); echo $N > ${FILE_SUCCESS}
      N=$((`cat ${FILE_FATAL}`+${TESTS_FATAL})); echo $N > ${FILE_FATAL}
      N=$((`cat ${FILE_FAILED}`+${TESTS_FAILED})); echo $N > ${FILE_FAILED}
      N=$((`cat ${FILE_BROKEN}`+${TESTS_BROKEN})); echo $N > ${FILE_BROKEN}
      N=$((`cat ${FILE_FIXED}`+${TESTS_FIXED})); echo $N > ${FILE_FIXED}
      N=$((`cat ${FILE_TOTAL}`+${TESTS_TOTAL})); echo $N > ${FILE_TOTAL}
      unlock
    ) &
    if [ ${NTH} -ge $THREADS ]; then
      NTH=1
      wait
      cat $TFS
      rm -f $TFS
      TFS=""
    fi
  fi
}

R=$PWD
# Run all tests.
T="t"; [ -n "$1" ] && T="$1"
[ -f "$T" -a -x "$T" ] && exec $T
cd $T || die "t/ doesn't exist"
for file in * ; do
   [ "$file" = '*' ] && break
   if [ -d "$file" ]; then
       for file2 in $file/*; do
           NAME=`basename $file2`
           TEST_NAME=$NAME
           runfile ./$file/ $NAME
       done
   elif [ ! -x "$file" ]; then  # Only run files marked as executable.
      print_found_nonexec "$file"
   else
      NAME=`basename $file`
      TEST_NAME=$NAME
      runfile ./ ${file}
   fi
done

wait
cat $TFS
rm -f $TFS
TFS=""

if [ $THREADS -gt 1 ]; then
    TESTS_SUCCESS=$(cat ${FILE_SUCCESS})
    TESTS_FATAL=$(cat ${FILE_FATAL})
    TESTS_FAILED=$(cat ${FILE_FAILED})
    TESTS_FIXED=$(cat ${FILE_FIXED})
    TESTS_BROKEN=$(cat ${FILE_BROKEN})
    TESTS_TOTAL=$(cat ${FILE_TOTAL})
fi
rm -f ${FILES}

print_report

save_stats

# Exit codes, as documented in README.md
if [ "${TESTS_FATAL}" -gt 0 ]; then
    echo "ESSENTIAL TEST HAS FAILED"
    exit 1
elif [ "${TESTS_FAILED}" -gt 0 ]; then
    exit 2
else
    exit 0
fi
