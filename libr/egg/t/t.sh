if [ "$1" = -s ]; then
	ragg2 -s t.r > fail-t-$0.s
	cp t fail-t-$0
	exit 0
fi
ragg2 -FO t.r
rarun2 '' program=./t timeout=1 > t.o 
#2>/dev/null
if [ $? = "${EXIT}" -a "`cat t.o`" = "${OUTPUT}" ]; then
	out=SUCCESS
	rm -f fail-t-$0*
else
	out=FAIL
	ragg2 -s t.r > fail-t-$0.s
	cp -f t fail-t-$0
	cp -f t.r fail-t-$0.r
fi
echo "Testing $0.. $out"
rm -f t.r t.o
