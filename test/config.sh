# CONFIGURATION FILE FOR TEST SUITE #
r2=../../binr/radare2/radare2
if [ -z "${DEBUG}" ]; then
:
#DEBUG=1
#DEBUG=valgrind
fi
export r2 DEBUG
