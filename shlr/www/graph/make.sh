cd img
for a in *.gif ; do
	printf '<img src="data:image/png;base64,'
	printf "%s" `base64 $a | tr '\r' ' '`
	echo '" alt="'$a'">'
done
