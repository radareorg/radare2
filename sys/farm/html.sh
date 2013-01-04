#!/bin/sh
cd `dirname $PWD/$0` || exit
test -f ./bins.sh && ./bins.sh

# gen htmls
for a in log/*.log ; do
	b=$(sed -e 's,.log$,.html,' $a)
	r=$(sed -e 's,.log$,.ret,'  $a)
	t=$(sed -e 's,.log$,.time,' $a)
	c=$(sed -e 's,.log$,.cpu,'  $a)
	echo "<html><body style=background-color:black;color:white;font-family:Verdana>" > $b
	echo "<h1><a href=./>index</a></h1>" >> $b
	echo "<h1>$a</h1>" >> $b
	allocas=$(grep -ce "alloca'" $a)
	formats=$(grep -c -e "in format" -e "format'" $a)
	unused=$(grep -c -e "not used" -e unused $a)
	casts=$(grep -ce incompatible $a)
	warnings=$(grep "warning:" $a)
	undefineds=$(grep undefined $a)
	errors=$(grep -c -e error: -e 'returned 1' $a)
	if [ -f $t ]; then
		echo "<h2>time:</h2>" >> $b
		echo "<pre>" >> $b
		cat $t >> $b
		echo "</pre>" >> $b
	fi
	if [ -f $c ]; then
		echo "<h2>cpu:</h2>" >> $b
		echo "<pre>" >> $b
		cat $c >> $b
		echo "</pre>" >> $b
	fi
	echo "<pre>" >> $b
	echo "<h2>warnings: $warnings</h2>" >> $b
	echo "read below" >> $b
	echo "<h2>errors: $errors + $undefineds</h2>" >> $b
	echo "read below" >> $b
	echo "<h2>return: "`cat $r`"</h2>" >> $b
	echo "<h2>casts: $casts</h2>" >> $b
	grep -e "incompatible" $a | awk '{
		gsub(/incompatible (.*)$/,"<b style=color:yellow>incompatible &</b>");
		print}' >> $b
	echo "<h2>formats: $formats</h2>" >> $b
	grep -e "in format" -e "format'" $a | awk '{
		gsub(/format(.*)$/,"<b style=color:yellow>format &</b>");
		print}' >> $b
	echo "<h2>allocas: $allocas</h2>" >> $b
	grep "alloca'" $a | awk '{
		gsub(/warning\: (.*)$/,"<b style=color:yellow>&</b>");
		print}' >> $b
	echo "<h2>undefined: $undefineds</h2>" >> $b
	grep -C 2 undefined $a | awk '{
		gsub(/undefined (.*)$/,"<b style=color:orange>&</b>");
		print}' >> $b
	echo "<h2>errors:</h2>" >> $b
	grep -e Error -e error: $a | awk '{
		gsub(/rror\: (.*)$/,"<b style=color:red>&</b>");
		print}' >> $b
	grep -C 2 'returned 1' $a | awk '{
		gsub(/^---$/,"<br />");
		gsub(/^(.*)$/,"<b style=color:red>&</b>");
		print}' >> $b
	echo "<h2>unused: $unused</h2>" >> $b
	grep -e "not used" -e unused $a | awk '{
		gsub(/warning\: (.*)$/,"<b style=color:yellow>&</b>");
		print}' >> $b
	echo "<h2>warnings:</h2>" >> $b
	grep warning: $a | awk '{
		gsub(/warning\: (.*)$/,"<b style=color:yellow>&</b>");
		print}' >> $b
	echo "<h2>build:</h2>" >> $b
	awk '{
		gsub(/warning\: (.*)$/,"<b style=color:yellow>warning: &</b>");
		gsub(/error\: (.*)$/,"<b style=color:red>&</b>");
		print}' $a >> $b
	echo "<pre></body></html>" >> $b
done

# gen index
cat <<EOF > log/index.html
<html>
<title>r2 build farm</title>
<body style=background-color:black;color:white;font-family:Verdana>
<h1>r2 build farm</h1>
<h2>bins</h2>
EOF
(cd log/bin && 
for a in * ; do
	s=$(du -hs $a |awk '{print $1}')
	echo "<h3><a href='bin/$a'>$a</a> ($s)</h3>" >> ../index.html
done
)

echo "<h2>builds</h2>" >> log/index.html
for a in `ls -rt log/*.log | tac`; do
	[ $a = log/index.html ] && continue
	f=$(echo $a | sed -e 's,log/,,' -e s,.log,,)
	l=log/$f.log
	ft=log/$f.time
	n=$(sed -e 's,-, ,g' $f)
	t=$(awk '/real/{print $2}' $ft)
	warnings=$(grep -c "warning:" $l)
	errors=$(grep -c "error:" $l)
	echo "<h3><a href=$f.html>$n</a> (<font color=yellow>w:</font>$warnings <font color=red>e:</font>$errors $t)</h3>" >> log/index.html
done

cat <<EOF >> log/index.html
</body>
</html>
EOF
