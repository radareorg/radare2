#!/usr/bin/spp
Content-Type: text/html
Status: 200 OK

<html>
<head>
 <title>radare</title>
</head>
<body>


Hello <{system echo beep }>
<br />
hello <{system echo world}>


<{switch QUERY_STRING}>
<{case foo}>
  foo
<{case bar}>
  bar
<{endswitch}>

<{ifeq QUERY_STRING foo}>
 <a href="?">go back</a> <br />
<{else}>
 <a href="?foo">click here</a> <br />
<{endif}>

<br />
<{system export | perl -ne 's/\n/<br>/ ;print'}>
</html>
