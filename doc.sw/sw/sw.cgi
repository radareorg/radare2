#!/bin/sh
# sw - suckless webframework - 2010 - nibble <develsec.org>

# Configuration
[ -n "${SWCONF}" ] && . ${SWCONF} || . sw.conf

echo "Content-type: text/html"
echo
echo "<!doctype html>"

if [ -z "`echo "${REQUEST_URI}" | grep -F "${BIN}"`" ] || \
   [ -n "`echo "${REQUEST_URI}" | grep -e "[^a-zA-Z0-9_\./ -]\+"`" ]; then
	echo "<html><head><meta http-equiv=\"Refresh\" content=\"0; url=${PREFIX}${BIN}\"></head></html>"
	echo "Invalid configuration ${REQUEST_URI} .. ${BIN}" > /dev/stderr
	exit 1
fi

QUERY=`echo "${REQUEST_URI}" | sed -e "s,.*${BIN}/*\(.*\),\1,"`
DIR=""
FILE="index.md"
if [ -n "${QUERY}" ]; then
	if [ -f "${SITE}/${QUERY}" ]; then
		DIR=`dirname ${QUERY} | sed -e "s,[/\.]*$,,"`
		FILE=${QUERY}
	elif [ -d "${SITE}/${QUERY}" ]; then
		DIR=`echo "${QUERY}" | sed -e "s,/*$,,"`
		FILE="$DIR/index.md"
	fi
fi

sw_menu() {
	BL=`echo "${BL}" | sed -e "s/ \+\|^/ -e /g"`
	echo "<ul>"
	# absolute paz
	#[ -n "${DIR}" ] && echo "<li><a href=\"`dirname ${PREFIX}${BIN}/${DIR}`\">..</a></li>"
	# relative fun
	[ -n "${DIR}" ] && echo "<li><a href=\"../index.html\">..</a></li>"
	for i in `ls ${SITE}/${DIR} | grep -v ${BL} ` ; do
		NAME=`echo "${i}" | sed -e "s/\..*$//" -e "s/_/ /g"`
		# THIS IS RELATIVE STATIC FUN
		[ -z "`echo $i | grep md$`" ] && i="$i/index.md"
		echo "<li><a href=\"${PREFIX}${BIN}/${i}\">${NAME}</a></li>"
		# THIS IS FOR WEB
		#echo "<li><a href=\"${PREFIX}${BIN}/${DIR}/${i}\">${NAME}</a></li>"
	done
	echo "</ul>"
}

sw_main() {
	if [ -n "`echo "${FILE}" | grep -e "^.*\.md$"`" ]; then
		[ -f "${SITE}/${FILE}" ] && ${MDHANDLER} "${SITE}/${FILE}"
	else
		echo "Download <a href=\"${PREFIX}${SITE}/${FILE}\">${FILE}</a>"
	fi
}

# Header
cat << _header_
<html>
<head>
<title>${TITLE}</title>
<link rel="stylesheet" href="${PREFIX}${STYLE}" type="text/css">
<link rel="icon" href="/favicon.png" type="image/png">
<meta charset="UTF-8">
</head>
<body>
<div class="header">
<h1 class="headerTitle">
<a href="${PREFIX}${BIN}">${TITLE}</a> <span class="headerSubtitle">${SUBTITLE}</span>
</h1>
</div>
_header_
# Menu
echo "<div id=\"side-bar\">"
sw_menu
echo "</div>"
# Body
echo "<div id=\"main\">"
sw_main
echo "</div>"
# Footer
cat << _footer_
<div id="footer">
<div class="right"><a href="http://nibble.develsec.org/sw.cgi/projects/sw.md">Powered by sw</a></div>
</div>
</body>
</html>
_footer_

exit 0
