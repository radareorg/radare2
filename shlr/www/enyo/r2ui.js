/* not used. must be deprecated or merged */

var r2ui = {}
r2ui.consoleExec = function () {
	var xx = document.getElementById ('consoleBody');
	if (!xx) alert ("NO CONDSOEL DBODY");
	var str = document.getElementById ('consoleEntry');
	if (str) str = str.value;
	r2.cmd (str, function (res) {
		document.getElementById ('consoleBody').innerHTML = res;
		var entry = document.getElementById ('consoleEntry');
		entry.value = "";
	});
}

r2ui.logger = null;
function init () {
	logger = r2.getTextLogger ().on ("message", function (msg) {
		var out = document.getElementById ('logsBody');
		out.innerHTML += "<br />"+msg.text; // XXX XSS
	});
	// logger.send ("hello world");
	logger.autorefresh (3);

}
r2ui.sendMessage = function () {
	var msg = document.getElementById ("logsEntry").value;
	if (!logger) init();
	if (logger) logger.send (msg);
	document.getElementById ("logsEntry").value = "";
}

function li (off, name) {
	return "<li><pre><b>0x"+off.toString (16)+"</b>  "+name+"</pre></li>";
}
r2ui.initSections = function () {
	r2.bin_sections (function (sections) {
		var str = "";
		for (var i=0; i<sections.length; i++) {
			var s = sections[i];
			str += li (s.offset, s.name);
		}
		document.getElementById ("sectionsBody").innerHTML = str;
	});
}
r2ui.initSymbols = function () {
	r2.bin_symbols (function (symbols) {
		var str = "";
		for (var i=0; i<symbols.length; i++) {
			var s = symbols[i];
			str += li (s.offset, s.name);
		}
		document.getElementById ("symbolsBody").innerHTML = str;
	});
}

r2ui.initHexdump = function () {
	r2.cmd ("x 1024", function (x) {
		document.getElementById ("hexdumpBody").innerHTML = x;
	});
}

/* block dis */
var prev_curoff = 0;
var prev_lastoff = 0;
var next_curoff = 0;
var next_lastoff = 0;
var backward = false;
var display = "pd";

function less () {
	var oldoff = document.body.scrollHeight;
	backward = true;
	r2.cmd ("b", function (block) {
		r2.cmd ("s "+prev_curoff+"-"+block+";"+display, function (x) {
			x = filter_asm (x);
			var body = document.getElementById ('disasmBody').innerHTML;
			document.getElementById ('disasmBody').innerHTML = x + body;
			var newoff = document.body.scrollHeight;
			var d= newoff-oldoff;
			document.body.scrollTop = d;
		});
	});
}

function hasmore(x) {
	var a = document.getElementById ("more");
	var b = document.getElementById ("less");
	if (!a || !b) return;
	if (x) {
		a.style.visibility=b.style.visibility="visible";
	} else {
		a.style.visibility=b.style.visibility="hidden";
	}
}

function more () {
	backward = false;
	r2.cmd ("?v $l @ "+next_lastoff, function (oplen) {
		display = "pd";
		if (display == "px") oplen = 16;
		r2.cmd (display+" @ "+next_lastoff+"+"+oplen, function (x) {
			x = filter_asm (x);
			document.getElementById('disasmBody').innerHTML += x;
		});
	});
}
function filter_asm(x) {
	var curoff = backward? prev_curoff: next_curoff;;
	var lastoff = backward? prev_lastoff: next_lastoff;;
	var lines = x.split (/\n/g);
	r2.cmd ("s", function (x) { curoff = x; });
	for (var i=lines.length-1;i>0;i--)  {
		var a = lines[i].match (/0x([a-fA-F0-9]*)/);
		if (a && a.length>0) {
			lastoff = a[0].replace (/:/g, "");
			break;
		}
	}
	if (display == "afl") {
		hasmore (false);
		var z = "";
		for (var i=0;i<lines.length;i++)  {
			var row = lines[i].replace (/\ +/g," ").split (/ /g);
			z += row[0]+ "  "+row[3]+"\n";
		}
		x = z;
	} else
	if (display[0] == 'f') {
		hasmore (false);
		if (display[1] == 's') {
			var z = "";
			for (var i=0; i<lines.length; i++)  {
				var row = lines[i].replace (/\ +/g," ").split (/ /g);
				var mark = row[1]=='*'? '*': ' ';
				var space = row[2]? row[2]: row[1];
				if (!space) continue;
				z += row[0]+ " "+mark+" <a href=\"javascript:runcmd('fs "+
					space+"')\">"+space+"</a>\n";
			}
			x = z;
		} else {
		}
	} else
	if (display[0] == "i") {
		hasmore (false);
		if (display[1]) {
			var z = "";
			for (var i=0;i<lines.length;i++)  {
				var elems = lines[i].split (/ /g);
				var name = "";
				var addr = "";
				for (var j=0;j<elems.length;j++)  {
					var kv = elems[j].split (/=/);
					if (kv[0] == "addr") addr = kv[1];
					if (kv[0] == "name") name = kv[1];
					if (kv[0] == "string") name = kv[1];
				}
				z += addr+ "  "+name+"\n";
			}
			x = z;
		}
	} else hasmore (true);

	function haveDisasm(x) {
		if (x[0]=='p' && x[1]=='d') return true;
		if (x.indexOf (";pd") != -1) return true;
		return false;
	}
	if (haveDisasm (display)) {
		x = x.replace (/function:/g,"<span style=color:red>function:</span>");
		x = x.replace (/;(\s+)/g, ";");
		x = x.replace (/;(.*)/g, "// <span style='color:red'>$1</span>");
		x = x.replace (/(bl|call)/g, "<b style='color:green'>call</b>");
		x = x.replace (/(jmp|bne|beq|jnz|jae|jge|jbe|jg|je|jl|jz|jb|ja|jne)/g, "<b style='color:green'>$1</b>");
		x = x.replace (/(dword|qword|word|byte|movzx|movsxd|cmovz|mov\ |lea\ )/g, "<b style='color:grey'>$1</b>");
		x = x.replace (/(hlt|leave|retn|ret)/g, "<b style='color:red'>$1</b>");
		x = x.replace (/(add|sub|mul|div|shl|shr|and|not|xor|inc|dec|sar|sal)/g, "<b style='color:grey'>$1</b>");
		x = x.replace (/(push|pop)/g, "<b style='color:black'>$1</b>");
		x = x.replace (/(test|cmp)/g, "<b style='color:green'>$1</b>");
		x = x.replace (/nop/g, "<b style='color:blue'>nop</b>");
		x = x.replace (/(sym|fcn|imp|loc).(.*)/g, "<a href='javascript:r2ui.seek(\"$1.$2\")'>$1.$2</a>");
	}
	x = x.replace (/0x([a-zA-Z0-9]*)/g, "<a href='javascript:r2ui.seek(\"0x$1\")'>0x$1</a>");
// registers
	if (backward) {
		prev_curoff = curoff;
		prev_lastoff = lastoff;
	} else {
		next_curoff = curoff;
		next_lastoff = lastoff;
		if (!prev_curoff)
			prev_curoff = next_curoff;
	}
	return x;
}

var seekindex = 0;
var seekhistory = [];

function seek_undo() {
	seekindex--;
	seekhistory[seekhistory.length-1] = x;
}

function seek_redo() {
	seekindex++;
	if (seekindex>=seekhistory.length) {
		seekindex--;
		return;
	}
	seek (seekhistory[seekindex]);
}

function seek_do(x) {
	seekindex++;
	seekhistory[seekhistory.length] = x;
}

function seek(x,back) {
	seek_do (x)
	next_curoff = prev_curoff = x;
	//if (display[0] != 'p') setmode ('pd');
	r2.cmd ("s "+x, function (x) {
	//	if (display[0]=='f') display="pd";
		document.body.scrollTop = 0;
		r2ui.initDisasm ();
	});
}

r2ui.seek = seek;

r2ui.initDisasm = function () {
	r2.cmd ("pd 128", function (x) {
		x = filter_asm (x);
		document.getElementById ("disasmBody").innerHTML = x;
	});
}

r2ui.assembleOpcode = function () {
	var str = document.getElementById ("assembleOpcode").value;
	r2.cmd ("\"pa "+str+"\"", function (x) {
		document.getElementById ("assembleBytes").value = x;
	});
}

r2ui.assembleBytes = function () {
	var hex = document.getElementById ("assembleBytes").value;
	r2.cmd ("pi 1@b:"+hex, function (x) {
		document.getElementById ("assembleOpcode").value = x;
	});
}

r2ui.assembleWrite = function () {
	var hex = document.getElementById ("assembleBytes").value;
	var off = document.getElementById ("assembleOffset").value;
	r2.cmd ("s "+off+";wx "+hex, function (x) {
		Lungo.Notification.error('Oops', 'Cannot write bytes', 'file is read-only', 2);
		//document.getElementById ("assembleOpcode").value = x;
	});
}
