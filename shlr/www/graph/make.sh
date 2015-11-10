cd img
for FILE in *.gif ; do
	printf '<img src="data:image/png;base64,'
	printf "%s" `base64 $FILE | tr '\r' ' '`
	echo '" alt="'$FILE'">'
done
