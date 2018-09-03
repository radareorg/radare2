#!/bin/bash

print_var()
{
    VAR_NAME=$1
    VAR_VALUE=$2
    if [ "${VAR_VALUE}" != "" ] ; then
        printf "export %s=%q\n" "${VAR_NAME}" "${VAR_VALUE}"
    fi
}

env -0 | while IFS='=' read -r -d '' n v; do
    if [[ "${n}" =~ ^TRAVIS_* || "${n}" =~ ^R2* || "${n}" =~ SAN_* ]]; then
        print_var "${n}" "${v}"
    fi
done

# print extra variables
print_var CC "${CC}"
print_var CXX "${CXX}"
print_var CFLAGS "${CFLAGS}"
print_var LDFLAGS "${LDFLAGS}"
print_var CXXFLAGS "${CXXFLAGS}"
print_var INSTALL_SYSTEM "${INSTALL_SYSTEM}"
print_var MESON_OPTIONS "${MESON_OPTIONS}"
print_var COVERAGE "${COVERAGE}"
