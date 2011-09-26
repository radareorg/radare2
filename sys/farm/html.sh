#!/bin/sh
cd `dirname $PWD/$0` 
./bins.sh

# gen htmls
for a in log/*.log ; do
	b=$(echo $a|sed -e 's,.log$,.html,')
	r=$(echo $a|sed -e 's,.log$,.ret,')
	t=$(echo $a|sed -e 's,.log$,.time,')
	c=$(echo $a|sed -e 's,.log$,.cpu,')
	echo "<html><body style=background-color:black;color:white;font-family:Verdana>" > $b
	echo "<h1><a href=./>index</a></h1>" >> $b
	echo "<h1>$a</h1>" >> $b
	warnings=$(cat $a|grep warning: |wc -l)
	errors=$(cat $a|grep error: |wc -l)
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
	echo "<h2>warnings: $warnings</h2>" >> $b
	echo "<h2>errors: $errors</h2>" >> $b
	echo "<h2>return: "`cat $r`"</h2>" >> $b
	echo "<h2>warnings:</h2>" >> $b
	echo "<pre>" >> $b
	grep warning: $a | awk '{
		gsub(/warning\: (.*)$/,"<b style=color:yellow>warning: &</b>");
		print}' >> $b
	echo "<h2>errors:</h2>" >> $b
	grep error: $a | awk '{
		gsub(/error\: (.*)$/,"<b style=color:red>error: &</b>");
		print}' >> $b
	echo "<h2>build:</h2>" >> $b
	cat $a | awk '{
		gsub(/warning\: (.*)$/,"<b style=color:yellow>warning: &</b>");
		gsub(/error\: (.*)$/,"<b style=color:red>error: &</b>");
		print}' >> $b
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
	echo "<h3><a href='bin/$a'>$a</a></h3>" >> ../index.html
done
)

echo "<h2>bins</h2>" >> log/index.html
for a in `ls -rt log/*.log | tac`; do
	[ $a = log/index.html ] && continue
	f=$(echo $a | sed -e 's,log/,,' -e s,.log,,)
	l=log/$f.log
	ft=log/$f.time
	n=$(echo $f|sed -e 's,-, ,g')
	t=$(cat $ft |grep real|awk '{print $2}')
	warnings=$(cat $l|grep warning: |wc -l)
	errors=$(cat $l|grep error: |wc -l)
	echo "<h3><a href=$f.html>$n</a> (<font color=yellow>w:</font>$warnings <font color=red>e:</font>$errors $t)</h3>" >> log/index.html
done

cat <<EOF >> log/index.html
</body>
</html>
EOF
