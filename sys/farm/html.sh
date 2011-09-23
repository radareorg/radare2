#!/bin/sh

# gen htmls
for a in log/*.log ; do
	b=$(echo $a|sed -e 's,.log$,.html,')
	r=$(echo $a|sed -e 's,.log$,.ret,')
	echo "<html><body style=background-color:black;color:white;font-family:Verdana>" > $b
	echo "<h1><a href=./>index</a></h1>" >> $b
	echo "<h1>$a</h1>" >> $b
	warnings=$(cat $a|grep warning: |wc -l)
	errors=$(cat $a|grep error: |wc -l)
	echo "<h2>warnings: $warnings</h2>" >> $b
	echo "<h2>errors: $errors</h2>" >> $b
	echo "<h2>return: "`cat $r`"</h2>" >> $b
	echo "<pre>" >> $b
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
EOF

for a in log/*.html ; do
	[ $a = log/index.html ] && continue
	warnings=$(cat $a|grep warning: |wc -l)
	errors=$(cat $a|grep error: |wc -l)
	f=$(echo $a | sed -e 's,log/,,')
	n=$(echo $f | sed -e 's,.html,,' | sed -e 's,-, ,g')
	echo "<h2><a href=$f>$n</a></h2>" >> log/index.html
	echo "<h3>&nbsp;&nbsp;&nbsp;warnings: $warnings</h3>" >> log/index.html
	echo "<h3>&nbsp;&nbsp;&nbsp;errors: $errors</h3>" >> log/index.html
done

cat <<EOF >> log/index.html
</body>
</html>
EOF
