echo "
db entry0
dc
db -entry0
dc
q
">.a
cat .a | r2 -d 'printf "works\n"' >.o 2>/dev/null
if [ -n "`grep works .o`" ]; then
	echo "$0: ok"
else
	echo "$0: fail"
fi

rm -f .a .o
