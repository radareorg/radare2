# test suite tool for r_egg #
case "$1" in
-h)
	echo "Usage: $0 [-opt]"
	echo " -r : show source (.r)"
	echo " -s : show code (assembly)"
	echo " -b : show bytes (binary)"
	echo " -d : disassebly (code)"
	echo " -x : execute"
	echo " -t : create 't' program"
	;;
-t)
	ragg2 -FO t.r
	exit
	;;
-d)
	rasm2 -d `ragg2 t.r`
	;;
-b)
	ragg2 t.r
	;;
-r)
	cat t.r
	;;
-x)
	ragg2 -FO t.r
	./t
	;;
-s)
	ragg2 -s t.r > fail-t-$0.s
	cat fail-t-$0.s
	cp t fail-t-$0
	;;
*)
	ragg2 -FO t.r
	rarun2 '' program=./t timeout=1 > t.o 
	if [ $? = "${EXIT}" -a "`cat t.o`" = "${OUTPUT}" ]; then
		out=SUCCESS
		rm -f fail-t-$0*
	else
		out=FAIL
		ragg2 -s t.r 2>&1 > fail-t-$0.s
		cp -f t fail-t-$0
		cp -f t.r fail-t-$0.r
	fi
	echo "Testing $0.. $out"
	;;
esac
rm -f t.r t.o
exit 0
