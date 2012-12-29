#!/bin/sh
#
# e scr.html=true
# e cmd.graph=!htmlgraph.sh
# af
# agv $$
#

D=`dirname $0`
P=`basename $0`
L=`readlink $D/$P`
if [ -n "$L" ]; then
	D=`dirname $L`
	P=`basename $L`
fi

# TODO: handle this correctly
if [ -n "$1" ]; then DOTFILE="$1" ; fi
if [ -n "${DOTFILE}" -a ! -e "${DOTFILE}" ] ; then
	echo "cannot find ${DOTFILE}"
	exit 1
fi

T=`mktemp /tmp/htmlg.XXXXXX`.html

cat <<EOF >>$T
<?xml version="1.0" encoding="ISO-8859-1" ?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1" />
<title>js-graph.it homepage</title>
<script type="text/javascript" src="jsgraph.js"></script>
<link rel="stylesheet" type="text/css" href="jsgraph.css" />
<style>
p{
  white-space: pre;
  font-family: monospace;
  display: block;
}
body{
        overflow:hidden;
}
</style>
<script>
        <!--
                function onLoad()
                {
                        setMenu();
                        resizeCanvas();
                        initPageObjects();
                }
                
                /**
                 * Resizes the main canvas to the maximum visible height.
                 */
                function resizeCanvas()
                {
                        var divElement = document.getElementById("mainCanvas");
                        var screenHeight = window.innerHeight || document.body.offsetHeight;
                        divElement.style.height = (screenHeight - 16) + "px";
                }
        
                /**
                 * sets the active menu scanning for a menu item which url is a prefix 
                 * of the one of the current page ignoring file extension.
                 * Nice trick!
                 */
                function setMenu()
                {
                        var url = document.location.href;
                        // strip extension
                        url = stripExtension(url);
                        
                        var ulElement = document.getElementById("menu");
                        var links = ulElement.getElementsByTagName("A");
                        var i;
                        for(i = 0; i < links.length; i++)
                        {
                                if(url.indexOf(stripExtension(links[i].href)) == 0)
                                {
                                        links[i].className = "active_menu";
                                        return;
                                }
                        }
                }
                
                /**
                 * Strips the file extension and everything after from a url
                 */
                function stripExtension(url)
                {
                        var lastDotPos = url.lastIndexOf('.');
                        if(lastDotPos > 0)
                                return url.substring(0, lastDotPos - 1);
                        else
                                return url;
                }
                
                /**
                 * this function opens a popup to show samples during explanations.
                 */
                function openSample(url)
                {
                        var popup = window.open(url, "sampleWindow", "width=400,height=300");
                        popup.focus();
                        return false;
                }
        //-->
</script>
</head>
<body onload="onLoad();">
<table class="main_table" style="height: 100%;">
<tr>
<td colspan=3>
        <a href=''>File</a> | Edit
</td>
</tr>
                <tr>
                        <td width="1" style="vertical-align: top;" class="menu">
                                <ul id="menu">
<select>
<option>Functions</option>
<option>Exports</option>
<option>Imports</option>
</select>

</ul>
</td>
<td style="vertical-align: top; padding: 0px;">
<div id="mainCanvas" class="canvas" style="width: 100%; height: 400px;">
EOF

cat ${DOTFILE} >> $T

cat <<EOF >> $T
</td>
<td width="1" style="vertical-align: top;" class="menu">
<ul id="menu"> </ul>
</td>
</tr>
</table>
</body>
</html>
EOF

cp -f $D/* /tmp
cd /tmp

if [ -e /usr/bin/open ]; then
	open $T
elif [ -e /usr/bin/xdg-open ]; then
	xdg-open $T
elif [ -n "${BROWSER+x}" ]; then
	$BROWSER $T
else
	echo "Could not find any installed browsers. Aborting."
fi
