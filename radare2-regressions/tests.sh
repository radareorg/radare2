#!/do/not/execute

# Copyright (C) 2011-2016  pancake<nopcode.org>
# Copyright (C) 2011-2012  Edd Barrett <vext01@gmail.com>
# Copyright (C) 2012     Simon Ruderich <simon@ruderich.org>
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

export RABIN2_NOPLUGINS=1
export RASM2_NOPLUGINS=1
export R2_NOPLUGINS=1
MACHINE_OS=$(uname -o 2> /dev/null)
GREP="$1"
GREP=""
DIFF=""
SKIP=0
cd `dirname $0` 2>/dev/null

# ignore encoding in sed
export LANG=C
export LC_CTYPE=C

# current workaround for timezone
export TZ=GMT

die() {
  echo "$1"
  exit 1
}

# Check for diff in system
DIFF=diff
diff --help 2>&1 | grep -q gnu
if [ "$?" = 0 ]; then
  DIFF_ARG="--strip-trailing-cr"
else
  gdiff --help 2>&1 | grep -q gnu
  if [ "$?" = 0 ]; then
    DIFF=gdiff
    DIFF_ARG="--strip-trailing-cr"
  else
    type diff > /dev/null 2>&1
    if [ $? = 0 ]; then
      echo "Cannot find GNU diff"
      DIFF="diff"
    else
      echo "Cannot find any diff in your system. wtf"
    fi
  fi
fi

printdiff() {
  if [ -n "${VERBOSE}" ]; then
    echo
    print_label Regression:
    echo "$0"
    print_label Command:
    echo "${R2CMD}"
    print_label File:
    echo "${FILE}"
    print_label Script:
    cat "${TMP_RAD}"
  fi
}

COUNT=0

run_test() {
  if [ "${HYPERPARALLEL}" = 1 ]; then
    ( echo "$(run_test_real)" ) &
  else
    run_test_real
  fi
}

run_test_real() {
  COUNT=$(($COUNT+1))
  if [ -n "${ONLY}" ]; then
    if [ "${ONLY}" != "${COUNT}" ]; then
      return
    fi
  fi
  # TODO: remove which dependency
  [ -z "${R2}" ] && R2=$(which radare2)
  PD="/tmp/r2-regressions/" # XXX
  if [ -n "${R2RWD}" ]; then
    PD="${R2RWD}"
  fi
  if [ -z "${R2}" ]; then
    echo "ERROR: Cannot find radare2 program in PATH"
    exit 1
  fi

  # add a prepended program to run test eg. zzuf
  if [ -n "${PREPEND}" ]; then
    export R2="${PREPEND} ${R2}"
  fi

  if [ -n "${GREP}" ]; then
    if [ -z "`echo \"${NAME}\" | grep \"${GREP}\"`" ]; then
      return
    fi
  fi

  # Set by run_tests.sh if all tests are run - otherwise get it from test
  # name.
  if [ -z "${TEST_NAME}" ]; then
    TEST_NAME=$(basename "$0" | sed 's/\.sh$//')
  fi

  NAME_TMP="${TEST_NAME}" #`basename $NAME` #"${TEST_NAME}"
  if [ -n "${NAME}" ]; then
    if [ "$NAME_TMP" = "$NAME" ]; then
      NAME_A="${NAME_TMP}"
      NAME_B=""
      NAME_TMP="${NAME_TMP}:"
    else
      NAME_A="${NAME_TMP}"
      NAME_B="${NAME}"
      NAME_TMP="${NAME_TMP}: ${NAME}"
    fi
  fi
  [ -n "${VALGRIND}" ] && NAME_TMP="${NAME_TMP} (valgrind)"

  if [ -n "${NOCOLOR}" ]; then
    printf "[  ]  ${COUNT}  %s: %-30s" "${NAME_A}" "${NAME_B}"
  else
    printf "\033[33m[  ]  ${COUNT}  %s: \033[0m%-30s" "${NAME_A}" "${NAME_B}" #"${NAME_TMP}"
  fi

  # Check required variables.
  if [ -z "${FILE}" ]; then
    test_failed "FILE missing!"
    test_reset
    return
  fi
  if [ -z "${SHELLCMD}" -a -z "${CMDS}" ]; then
    test_failed "CMDS missing!"
    test_reset
    return
  fi
  # ${EXPECT} can be empty. Don't check it.

  # Verbose mode is always used if only a single test is run.
  if [ -z "${R2_SOURCED}" ]; then
    if [ -z "${QUIET}" ]; then
      VERBOSE=1
    fi
  fi

  mkdir -p ${PD} || exit 1
  TMP_DIR="`mktemp -d "${PD}/${TEST_NAME}-XXXXXX"`"
  if [ $? != 0 ]; then
    echo "Please set R2RWD path to something different than /tmp/r2-regressions"
    exit 1
  fi
  TMP_NAM="${TMP_DIR}/nam" # test name ($NAME)
  TMP_RAD="${TMP_DIR}/rad" # test radare script
  TMP_OUT="${TMP_DIR}/out" # stdout
  TMP_EXP="${TMP_DIR}/exp" # expected output
  TMP_ERR="${TMP_DIR}/err" # stderr
  TMP_EXR="${TMP_DIR}/exr" # expected error
  TMP_VAL="${TMP_DIR}/val" # valgrind output
  TMP_BIN="${TMP_DIR}/bin" # the binary used
  TMP_ODF="${TMP_DIR}/odf" # output diff
  TMP_EDF="${TMP_DIR}/edf" # err diff

  : > "${TMP_OUT}"
  echo -n "$FILE" > "${TMP_BIN}"
  cat > "$TMP_NAM" << __EOF__
$TEST_NAME / $NAME
__EOF__
  if [ -n "${SHELLCMD}" ]; then
    R2CMD="$SHELLCMD"
  else
    # R2_ARGS must be defined by the user in cmdline f.ex -e io.vio=true
    # No colors and no user configs.
    if [ -n "${DEBUG}" ]; then
      R2ARGS="gdb --args ${R2} -e scr.color=0 -N -q -i ${TMP_RAD} ${R2_ARGS} ${ARGS} ${FILE}"
    else
      R2ARGS="${R2} -e scr.color=0 -N -q -i ${TMP_RAD} ${R2_ARGS} ${ARGS} ${FILE} > ${TMP_OUT} 2> ${TMP_ERR}"
    fi
    R2CMD=
    # Valgrind to detect memory corruption.
    if [ -n "${VALGRIND}" ]; then
      if [ -z ${VALGRIND_DIR+x} ]; then
        VALGRIND_REPORT=${TMP_VAL}
      else
        VALGRIND_REPORT=${VALGRIND_DIR}/${TEST_NAME}
      fi
      if [ -n "${VALGRIND_XML}" ]; then
        R2CMD="${VALGRIND} --xml=yes --xml-file=${VALGRIND_REPORT}.memcheck"
      else
        R2CMD="valgrind --error-exitcode=47 --log-file=${VALGRIND_REPORT}"
      fi
    fi
    R2CMD="${R2CMD} ${R2ARGS}"
    #if [ -n "${VERBOSE}" ]; then
      #echo #$R2CMD
    #fi
  fi

  # Put expected outcome and program to run in files and run the test.
  printf "%s\n" "${CMDS}" > ${TMP_RAD}
  printf "%s" "${EXPECT}" > ${TMP_EXP}
  printf "%s" "${EXPECT_ERR}" > ${TMP_EXR}
  if [ -n "${TIMEOUT}" ]; then
    eval "rarun2 timeout=${TIMEOUT} -- ${R2CMD}"
  else
    eval "${R2CMD}"
  fi
  CODE=$?
  if [ -n "${IGNORE_RC}" ]; then
    CODE=0
  fi
  if [ -n "${R2_SOURCED}" ]; then
    TESTS_TOTAL=$(( TESTS_TOTAL + 1 ))
  fi

  # ${FILTER} can be used to filter out random results to create stable
  # tests.
  if [ -n "${FILTER}" ]; then
    # Filter stdout.
    FILTER_CMD="cat ${TMP_OUT} | ${FILTER} > ${TMP_OUT}.filter"
    #if [ -n "${VERBOSE}" ]; then
    #  echo "Filter (stdout):  ${FILTER}"
    #fi
    eval "${FILTER_CMD}"
    mv "${TMP_OUT}.filter" "${TMP_OUT}"

    # Filter stderr.
    FILTER_CMD="cat ${TMP_ERR} | ${FILTER} > ${TMP_ERR}.filter"
    #if [ -n "${VERBOSE}" ]; then
    #  echo "Filter (stderr):  ${FILTER}"
    #fi
    eval "${FILTER_CMD}"
    mv "${TMP_ERR}.filter" "${TMP_ERR}"
  fi

  # Check if radare2 exited with correct exit code.
  if [ -n "${EXITCODE}" ]; then
    if [ ${CODE} -eq "${EXITCODE}" ]; then
      CODE=0
      EXITCODE=
    else
      EXITCODE=${CODE}
    fi
  fi
  if [ "${MACHINE_OS}" = "Msys" ] || [ "${MACHINE_OS}" = "Cygwin" ]; then
    cat "${TMP_OUT}" | tr -d '\r' > "${TMP_OUT}_fix"
    rm -f "${TMP_OUT}"
    mv "${TMP_OUT}_fix" "${TMP_OUT}"
  fi
  # Check if the output matched. (default to yes)
  ${DIFF} ${DIFF_ARG} -u "${TMP_EXP}" "${TMP_OUT}" > "${TMP_ODF}"
  OUT_CODE=0
  [ -s "${TMP_ODF}" ] && OUT_CODE=1
  if [ "${NOT_EXPECT}" = 1 ]; then
    if [ "${OUT_CODE}" = 0 ]; then
      OUT_CODE=1
    else
      OUT_CODE=0
    fi
  fi
  if [ "${IGNORE_ERR}" = 1 ]; then
    ERR_CODE=0
  else
    if [ "${MACHINE_OS}" = "Msys" ] || [ "${MACHINE_OS}" = "Cygwin" ]; then
      cat "${TMP_ERR}" | tr -d '\r' > "${TMP_ERR}_fix"
      rm -f "${TMP_ERR}"
      mv "${TMP_ERR}_fix" "${TMP_ERR}"
    fi
    ${DIFF} ${DIFF_ARG} -u "${TMP_EXR}" "${TMP_ERR}" > "${TMP_EDF}"
    ERR_CODE=0
    [ -s "${TMP_EDF}" ] && ERR_CODE=1
    if [ "${NOT_EXPECT}" = 1 ]; then
      if [ "${ERR_CODE}" = 0 ]; then
        ERR_CODE=1
      else
        ERR_CODE=0
      fi
    fi
    if [ "${ERR_CODE}" != 0 ]; then
      cat "${TMP_ERR}"
    fi
  fi

  if [ ${CODE} -eq 47 ]; then
    test_failed "valgrind error"
    if [ -n "${VERBOSE}" ]; then
      cat "${TMP_VAL}"
      echo
    fi
  elif [ -n "${EXITCODE}" ]; then
    test_failed "wrong exit code: ${EXITCODE}"
    printdiff
  elif [ ${CODE} -ne 0 ]; then
    test_failed "radare2 crashed"
    printdiff
    if [ -n "${VERBOSE}" ]; then
      cat "${TMP_OUT}"
      cat "${TMP_ERR}"
      echo
    fi
  elif [ ${OUT_CODE} -ne 0 ]; then
    test_failed
    printdiff
    if [ -n "${VERBOSE}" ]; then
      print_label Diff:
      if grep ^Binary "${TMP_ODF}"; then
        r2 -nqfcx "${TMP_EXP}" > "${TMP_DIR}/xhd"  # expected hexdump
        r2 -nqfcx "${TMP_OUT}" > "${TMP_DIR}/ohd"  # output hexdump
        ${DIFF} ${DIFF_ARG} -u "${TMP_DIR}/xhd" "${TMP_DIR}/ohd"
      else
        cat "${TMP_ODF}"
      fi
      echo
    fi
  elif [ ${ERR_CODE} -ne 0 ]; then
    test_failed
    printdiff
    if [ -n "${VERBOSE}" ]; then
      if grep ^Binary "${TMP_EDF}"; then
        r2 -nqfcx "${TMP_EXR}" > "${TMP_DIR}/xhr"  # expected err hexdump
        r2 -nqfcx "${TMP_ERR}" > "${TMP_DIR}/ehd"  # err output hexdump
        ${DIFF} ${DIFF_ARG} -u "${TMP_DIR}/xhr" "${TMP_DIR}/ehd"
      else
        cat "${TMP_EDF}"
      fi
      echo
    fi
  else
    test_success
  fi

  # remove the temporary output
  if [ "$KEEP_TMP" = "yes" ]; then
    echo "Temporary files saved in ${TMP_DIR}"
  else
    rm -rf "${TMP_DIR}"
  fi

  # Reset most variables in case the next test script doesn't set them.
  if [ "${REVERSERC}" = '1' ]; then
     export OUT_CODE=0
  fi
  test_reset

  return $OUT_CODE
}

test_reset() {
  [ -z "$NAME" ] && NAME=$0
  FILE="-"
  ARGS=
  CMDS=
  NOT_EXPECT=
  EXPECT=
  EXPECT_ERR=
  IGNORE_ERR=1
  FILTER=
  EXITCODE=
  BROKEN=
  SHELLCMD=
  PREPEND=
  REVERSERC=
  ESSENTIAL=
  SKIP=
  DEBUG=
}

test_reset

test_success() {
  if [ -z "${BROKEN}" ]; then
    print_success "OK"
  else
    print_fixed "FX"
  fi

  if [ -n "${R2_SOURCED}" ]; then
    if [ -z "${BROKEN}" ]; then
      TESTS_SUCCESS=$(( TESTS_SUCCESS + 1 ))
    else
      TESTS_FIXED=$(( TESTS_FIXED + 1 ))
    fi
  fi
}

test_failed() {
  if [ -n "${REVERSERC}" ]; then
    print_success "OK"
    SKIP=1
  fi
  if [ -z "${SKIP}" -o "${SKIP}" = 0 ]; then
    if [ -n "${ESSENTIAL}" ]; then
      print_failed "EF" # essential failure
      print_issue "${*}"
    else
      if [ -z "${BROKEN}" ]; then
        print_failed "XX"
        print_issue "${*}"
      else
        print_broken "BR"
      fi
    fi
  fi
  FAILED="${FAILED}${TEST_NAME}:"
  if [ -n "${R2_SOURCED}" ]; then
    if [ -n "${ESSENTIAL}" ]; then
      TESTS_FATAL=$(( TESTS_FATAL + 1 ))
    else
      if [ -z "${BROKEN}" ]; then
        TESTS_FAILED=$(( TESTS_FAILED + 1 ))
      else
        TESTS_BROKEN=$(( TESTS_BROKEN + 1 ))
      fi
    fi
  fi
}

if [ -n "${TRAVIS}" ]; then
  NL="\n"
else
  NL="\r"
fi

print_issue() {
  if [ -n "$1" ]; then
    if [ -n "${NOCOLOR}" ]; then
      printf "%b" "${NL}Issue: ${*}\n"
    else
      printf "%b" "${NL}\033[31mIssue: ${*}\033[0m\n"
    fi
  fi
}

print_success() {
  if [ -n "${NOOK}" ]; then
    printf "\033[2K\r"
  else
    if [ -n "${NOCOLOR}" ]; then
      printf "%b" "${NL}[${*}]\n"
    else
      printf "%b" "${NL}\033[32m[${*}]\033[0m\n"
    fi
  fi
}

print_broken() {
  if [ -n "${NOCOLOR}" ]; then
    printf "%b" "${NL}[${*}]\n"
  else
    printf "%b" "${NL}\033[34m[${*}]\033[0m\n"
  fi
}

print_failed() {
  if [ -n "${NOCOLOR}" ]; then
    printf "%b" "${NL}[${*}]\n"
  else
    printf "%b" "${NL}\033[31m[${*}]\033[0m\n"
  fi
}

print_fixed() {
  if [ -n "${NOCOLOR}" ]; then
    printf "%b" "${NL}[${*}]\n"
  else
    printf "%b" "${NL}\033[33m[${*}]\033[0m\n"
  fi
}

print_label() {
  if [ -n "${NOCOLOR}" ]; then
    printf "%s\n" $@
  else
    printf "\033[35m%s \033[0m" $@
  fi
}

print_found_nonexec() {
  MSG="Found non-executeable file '$1', skipping. (If it's a test, use chmod +x)"
  if [ -n "${NOCOLOR}" ]; then
    printf "%s\n" "$MSG"
  else
    printf "\033[1;31m%s\033[0m\n" "$MSG"
  fi
}

print_report() {
  if [ ! -z "${NOREPORT}" ]; then
  return
  fi

  echo
  echo "=== Report ==="
  echo
  printf "    SUCCESS"
  if [ "${TESTS_SUCCESS}" -gt 0 ]; then
    print_success "${TESTS_SUCCESS}"
  else
    print_failed "${TESTS_SUCCESS}"
  fi
  printf "    FIXED"
  if [ "${TESTS_FIXED}" -gt 0 ]; then
    print_fixed   "${TESTS_FIXED}"
  else
    print_fixed   0
  fi
  printf "    BROKEN"
  if [ "${TESTS_BROKEN}" -gt 0 ]; then
    print_broken "${TESTS_BROKEN}"
  else
    print_broken 0
  fi
  printf "    FATAL"
  if [ "${TESTS_FATAL}" -gt 0 ]; then
    print_failed "${TESTS_FATAL}"
  else
    print_failed 0
  fi
  printf "    FAILED"
  if [ "${TESTS_FAILED}" -gt 0 ]; then
    print_failed  "${TESTS_FAILED}"
  else
    print_failed  0
  fi
  printf "    TOTAL${NL}"
  print_label "[${TESTS_TOTAL}]"

  if [ "${TESTS_TOTAL}" != 0 ]; then
    dc -V > /dev/null 2>&1
    if [ $? = 0 ]; then
      BADBOYS=$((${TESTS_BROKEN}+${TESTS_FAILED}+${TESTS_FATAL}))
      BN=`echo "100 ${BADBOYS} * ${TESTS_TOTAL} / n" | dc`
      printf "    BROKENNESS${NL}"
      print_label "[${BN}%]"
      echo
    else
      echo " TOTAL"
    fi
  fi
}

save_stats(){
  cd $R
  STATS=`mktemp`
  V=`radare2 -v 2>/dev/null| grep ^rada| awk '{print $5}'`
  grep -v "^$V" "${STATS}" > "${STATS}.tmp"
  echo "$V,${TESTS_SUCCESS},${TESTS_FIXED},${TESTS_BROKEN},${TESTS_FAILED},${TESTS_FATAL},${FAILED}" >> "${STATS}.tmp"
  sort "${STATS}.tmp" > "${STATS}"
  cp -f "${STATS}" stats.csv 2> /dev/null
  rm -f "${STATS}.tmp" "${STATS}"
}
