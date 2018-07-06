#!/bin/bash

print_var()
{
    VAR_NAME=$1
    VAR_VALUE=$2
    if [ "${VAR_VALUE}" != "" ] ; then
	echo "${VAR_NAME}=${VAR_VALUE}"
    fi
}

# print all variables that start with TRAVIS_ and R2R_
env -0 | while IFS='=' read -r -d '' n v; do
    if [[ "${n}" =~ ^TRAVIS_* || "${n}" =~ ^R2R_* ]]; then
	print_var "${n}" "${v}"
    fi
done

# print extra variables
print_var CC "${CC}"
print_var CXX "${CXX}"
print_var CFLAGS "${CFLAGS}"
print_var LDFLAGS "${LDFLAGS}"
print_var CXXFLAGS "${CXXFLAGS}"

