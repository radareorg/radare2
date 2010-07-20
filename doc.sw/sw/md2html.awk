#!/usr/bin/awk -f
#
# by: Jesus Galan (yiyus) 2009
#
# Usage: md2html.awk file.md > file.html
# See: http://4l77.com/src/md2html.awk

function eschtml(t) {
	gsub("&", "\\&amp;", t);
	gsub("<", "\\&lt;", t);
	return t;
}

function oprint(t){
	if(nr == 0)
		print t;
	else
		otext = otext "\n" t;
}

function subref(id){
	for(; nr > 0 && sub("<<" id, ref[id], otext); nr--);
	if(nr == 0 && otext) {
		print otext;
		otext = "";
	}
}

function nextil(t) {
	if(!match(t, /[`<&\[*_\\-]|(\!\[)/))
		return t;
	t1 = substr(t, 1, RSTART - 1);
	tag = substr(t, RSTART, RLENGTH);
	t2 = substr(t, RSTART + RLENGTH);
	if(ilcode && tag != "`")
		return eschtml(t1 tag) nextil(t2);
	# Backslash escaping
	if(tag == "\\"){
		if(match(t2, /^[\\`*_{}\[\]()#+\-\.!]/)){
			tag = substr(t2, 1, 1);
			t2 = substr(t2, 2);
		}
		return t1 tag nextil(t2);
	}
	# Dashes
	if(tag == "-"){
		if(sub(/^-/, "", t2))
			tag = "&#8212;";
		return t1 tag nextil(t2);
	}
	# Inline Code
	if(tag == "`"){
		if(sub(/^`/, "", t2)){
			if(!match(t2, /``/))
				return t1 "&#8221;" nextil(t2);
			ilcode2 = !ilcode2;
		}
		else if(ilcode2)
			return t1 tag nextil(t2);
		tag = "<code>";
		if(ilcode){
			t1 = eschtml(t1);
			tag = "</code>";
		}
		ilcode = !ilcode;
		return t1 tag nextil(t2);
	}
	if(tag == "<"){
	# Autolinks
		if(match(t2, /^[^ 	]+[\.@][^ 	]+>/)){
			url = eschtml(substr(t2, 1, RLENGTH - 1));
			t2 = substr(t2, RLENGTH + 1);
			linktext = url;
			if(match(url, /@/) && !match(url, /^mailto:/))
				url = "mailto:" url;
			return t1 "<a href=\"" url "\">" linktext "</a>" nextil(t2);
		}
	# Html tags
		if(match(t2, /^[A-Za-z\/!][^>]*>/)){
			tag = tag substr(t2, RSTART, RLENGTH);
			t2 = substr(t2, RLENGTH + 1);
			return t1 tag nextil(t2);
		}
		return t1 "&lt;" nextil(t2);
	}
	# Html special entities
	if(tag == "&"){
		if(match(t2, /^#?[A-Za-z0-9]+;/)){
			tag = tag substr(t2, RSTART, RLENGTH);
			t2 = substr(t2, RLENGTH + 1);
			return t1 tag nextil(t2);
		}
		return t1 "&amp;" nextil(t2);
	}
	# Images
	if(tag == "!["){
		if(!match(t2, /(\[.*\])|(\(.*\))/))
			return t1 tag nextil(t2);
		match(t2, /^[^\]]*/);
		alt = substr(t2, 1, RLENGTH);
		t2 = substr(t2, RLENGTH + 2);
		if(match(t2, /^\(/)){
			# Inline
			sub(/^\(/, "", t2);
			match(t2, /^[^\)]+/);
			url = eschtml(substr(t2, 1, RLENGTH));
			t2 = substr(t2, RLENGTH + 2);
			title = "";
			if(match(url, /[ 	]+\".*\"[ 	]*$/)) {
				title = substr(url, RSTART, RLENGTH);
				url = substr(url, 1, RSTART - 1);
				match(title, /\".*\"/);
				title = " title=\"" substr(title, RSTART + 1, RLENGTH - 2) "\"";
			}
			if(match(url, /^<.*>$/))
				url = substr(url, 2, RLENGTH - 2);
			return t1 "<img src=\"" url "\" alt=\"" alt "\"" title " />" nextil(t2);
		}
		else{
			# Referenced
			sub(/^ ?\[/, "", t2);
			id = alt;
			if(match(t2, /^[^\]]+/))
				id = substr(t2, 1, RLENGTH);
			t2 = substr(t2, RLENGTH + 2);
			if(ref[id])
				r = ref[id];
			else{
				r = "<<" id;
				nr++;
			}
			return t1 "<img src=\"" r "\" alt=\"" alt "\" />" nextil(t2);
		}
	}
	# Links
	if(tag == "["){
		if(!match(t2, /(\[.*\])|(\(.*\))/))
			return t1 tag nextil(t2);
		match(t2, /^[^\]]*(\[[^\]]*\][^\]]*)*/);
		linktext = substr(t2, 1, RLENGTH);
		t2 = substr(t2, RLENGTH + 2);
		if(match(t2, /^\(/)){
			# Inline
			match(t2, /^[^\)]+(\([^\)]+\)[^\)]*)*/);
			url = substr(t2, 2, RLENGTH - 1);
			pt2 = substr(t2, RLENGTH + 2);
			title = "";
			if(match(url, /[ 	]+\".*\"[ 	]*$/)) {
				title = substr(url, RSTART, RLENGTH);
				url = substr(url, 1, RSTART - 1);
				match(title, /\".*\"/);
				title = " title=\"" substr(title, RSTART + 1, RLENGTH - 2) "\"";
			}
			if(match(url, /^<.*>$/))
				url = substr(url, 2, RLENGTH - 2);
			url = eschtml(url);
			return t1 "<a href=\"" url "\"" title ">" nextil(linktext) "</a>" nextil(pt2);
		}
		else{
			# Referenced
			sub(/^ ?\[/, "", t2);
			id = linktext;
			if(match(t2, /^[^\]]+/))
				id = substr(t2, 1, RLENGTH);
			t2 = substr(t2, RLENGTH + 2);
			if(ref[id])
				r = ref[id];
			else{
				r = "<<" id;
				nr++;
			}
			pt2 = t2;
			return t1 "<a href=\"" r "\" />" nextil(linktext) "</a>" nextil(pt2);
		}
	}
	# Emphasis
	if(match(tag, /[*_]/)){
		ntag = tag;
		if(sub("^" tag, "", t2)){
			if(stag[ns] == tag && match(t2, "^" tag))
				t2 = tag t2;
			else
				ntag = tag tag
		}
		n = length(ntag);
		tag = (n == 2) ? "strong" : "em";
		if(match(t1, / $/) && match(t2, /^ /))
			return t1 tag nextil(t2);
		if(stag[ns] == ntag){
			tag = "/" tag;
			ns--;
		}
		else
			stag[++ns] = ntag;
		tag = "<" tag ">";
		return t1 tag nextil(t2);
	}
}

function inline(t) {
	ilcode = 0;
	ilcode2 = 0;
	ns = 0;
	
	return nextil(t);
}

function printp(tag) {
	if(!match(text, /^[ 	]*$/)){
		text = inline(text);
		if(tag != "")
			oprint("<" tag ">" text "</" tag ">");
		else
			oprint(text);
	}
	text = "";
}

BEGIN {
	blank = 0;
	code = 0;
	hr = 0;
	html = 0;
	nl = 0;
	nr = 0;
	otext = "";
	text = "";
	par = "p";
}

# References
!code && /^ *\[[^\]]*\]:[ 	]+/ {
	sub(/^ *\[/, "");
	match($0, /\]/);
	id = substr($0, 1, RSTART - 1);
	sub(id "\\]:[ 	]+", "");
	title = "";
	if(match($0, /\".*\"$/))
		title = "\" title=\"" substr($0, RSTART + 1, RLENGTH - 2);
	sub(/[ 	]+\".*\"$/, "");
	url = eschtml($0);
	ref[id] = url title;

	subref(id);
	next;
}

# html
!html && /^<(address|blockquote|center|dir|div|dl|fieldset|form|h[1-6r]|\
isindex|menu|noframes|noscript|ol|p|pre|table|ul|!--)/ {
	if(code)
		oprint("</pre></code>");
	for(; !text && block[nl] == "blockquote"; nl--)
		oprint("</blockquote>");
	match($0, /^<(address|blockquote|center|dir|div|dl|fieldset|form|h[1-6r]|\
	isindex|menu|noframes|noscript|ol|p|pre|table|ul|!--)/);
	htag = substr($0, 2, RLENGTH - 1);
	if(!match($0, "(<\\/" htag ">)|((^<hr ?\\/?)|(--)>$)"))
		html = 1;
	if(html && match($0, /^<hr/))
		hr = 1;
	oprint($0);
	next;
}

html && (/(^<\/(address|blockquote|center|dir|div|dl|fieldset|form|h[1-6r]|\
isindex|menu|noframes|noscript|ol|p|pre|table|ul).*)|(--)>$/ ||
(hr && />$/)) {
	html = 0;
	hr = 0;
	oprint($0);
	next;
}

html {
	oprint($0);
	next;
}

# List and quote blocks

#   Remove indentation
{
	for(nnl = 0; nnl < nl; nnl++)
		if((match(block[nnl + 1], /[ou]l/) && !sub(/^(    |	)/, "")) || \
		(block[nnl + 1] == "blockquote" && !sub(/^> ?/, "")))
			break;
}
nnl < nl && !blank && text && ! /^ ? ? ?([*+-]|([0-9]+\.)+)( +|	)/ { nnl = nl; }
#   Quote blocks
{ 
	while(sub(/^> /, ""))
		nblock[++nnl] = "blockquote";
}
#   Horizontal rules
{ hr = 0; }
(blank || (!text && !code)) && /^ ? ? ?([-*_][ 	]*)([-*_][ 	]*)([-*_][ 	]*)+$/ {
	if(code){
		oprint("</pre></code>");
		code = 0;
	}
	blank = 0;
	nnl = 0;
	hr = 1;
}
#   List items
block[nl] ~ /[ou]l/ && /^$/ {
	blank = 1;
	next;
}
{ newli = 0; }
!hr && (nnl != nl || !text || block[nl] ~ /[ou]l/) && /^ ? ? ?[*+-]( +|	)/ {
	sub(/^ ? ? ?[*+-]( +|	)/, "");
	nnl++;
	nblock[nnl] = "ul";
	newli = 1;
}
(nnl != nl || !text || block[nl] ~ /[ou]l/) && /^ ? ? ?([0-9]+\.)+( +|	)/ {
	sub(/^ ? ? ?([0-9]+\.)+( +|	)/, "");
	nnl++;
	nblock[nnl] = "ol";
	newli = 1;
}
newli { 
	if(blank && nnl == nl && !par)
		par = "p";
	blank = 0;
	printp(par);
	if(nnl == nl && block[nl] == nblock[nl])
		oprint("</li><li>");
}
blank && ! /^$/ {
	if(match(block[nnl], /[ou]l/) && !par)
		par = "p";
	printp(par);
	par = "p";
	blank = 0;
}
		
# Close old blocks and open new ones
nnl != nl || nblock[nl] != block[nl] {
	if(code){
		oprint("</pre></code>");
		code = 0;
	}
	printp(par);
	b = (nnl > nl) ? nblock[nnl] : block[nnl];
	par = (match(b, /[ou]l/)) ? "" : "p";
}
nnl < nl || (nnl == nl && nblock[nl] != block[nl]) {
	for(; nl > nnl || (nnl == nl && pblock[nl] != block[nl]); nl--){
		if(match(block[nl], /[ou]l/))
			oprint("</li>");
		oprint("</" block[nl] ">");
	}
}
nnl > nl {
	for(; nl < nnl; nl++){
		block[nl + 1] = nblock[nl + 1];
		oprint("<" block[nl + 1] ">");
		if(match(block[nl + 1], /[ou]l/))
			oprint("<li>");
	}
}
hr {
	oprint("<hr>");
	next;
}

# Code blocks
code && /^$/ { 
	if(blanK)
		oprint("");
	blank = 1;
	next;
}
!text && sub(/^(	|    )/, "") {
	if(blanK)
		oprint("");
	blank = 0;
	if(!code)
		oprint("<code><pre>");
	code = 1;
	$0 = eschtml($0);
	oprint($0);
	next;
}
code {
	oprint("</pre></code>");
	code = 0;
}

# Setex-style Headers
text && /^=+$/ {printp("h1"); next;}
text && /^-+$/ {printp("h2"); next;} 

# Atx-Style headers
/^#+/ && (!newli || par=="p" || /^##/) {
	for(n = 0; n < 6 && sub(/^# */, ""); n++)
		sub(/#$/, "");
	par = "h" n;
}

# Paragraph	
/^$/ {
	printp(par);
	par = "p";
	next;
}

# Add text
{ text = (text ? text " " : "") $0; }

END {
	if(code){
		oprint("</pre></code>");
		code = 0;
	}
	printp(par);
	for(; nl > 0; nl--){
		if(match(block[nl], /[ou]l/))
			oprint("</li>");
		oprint("</" block[nl] ">");
	}
	gsub(/<<[^\"]*/, "", otext);
	print(otext);
}
