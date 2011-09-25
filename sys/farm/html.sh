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
EOF

for a in log/*.html ; do
	[ $a = log/index.html ] && continue
	f=$(echo $a | sed -e 's,log/,,')
	l=log/$(echo $f | sed -e 's,.html,.log,')
	n=$(echo $f | sed -e 's,.html,,' | sed -e 's,-, ,g')
	warnings=$(cat $l|grep warning: |wc -l)
	errors=$(cat $l|grep error: |wc -l)
	echo "<h2><a href=$f>$n</a> (w:$warnings e:$errors)</h2>" >> log/index.html
done

cat <<EOF >> log/index.html
</body>
</html>
EOF
