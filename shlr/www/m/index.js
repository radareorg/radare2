
var update = function() {/* nop */}
var inColor = true;
var lastView = 'pd';

function uiButton(href,label,type) {
if (type=='active') {
	return '&nbsp;<a href="'+href.replace(/"/g,"'")+'" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast" style="background-color:#f04040 !important">'+label+'</a>';
}
	return '&nbsp;<a href="'+href.replace(/"/g,"'")+'" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">'+label+'</a>';
}

function clickableOffsets(x) {
	x = x.replace (/0x([a-zA-Z0-9]*)/g,
		"<a href='javascript:seek(\"0x$1\")'>0x$1</a>");
	x = x.replace (/sym\.([\.a-zA-Z0-9]*)/g,
		"<a href='javascript:seek(\"sym.$1\")'>sym.$1</a>");
	x = x.replace (/fcn\.([\.a-zA-Z0-9]*)/g,
		"<a href='javascript:seek(\"fcn.$1\")'>fcn.$1</a>");
	return x;
}

function write() {
	var str = prompt ("hexpairs, quoted string or :assembly");
	if (str != "") {
		switch (str[0]) {
		case ':':
			str = str.substring(1);
			r2.cmd ('"wa '+str+'"', update);
			break;
		case '"':
			str = str.replace(/"/g, '');
			r2.cmd ("w "+str, update);
			break;
		default:
			r2.cmd ("wx "+str, update);
			break;
		}
	}
}

function comment() {
	var addr = prompt ("comment");
	if (addr) {
		if (addr=="-") {
			r2.cmd("CC-");
		} else {
			r2.cmd("\"CC "+addr+"\"");
		}
		update();
	}
}

function flag() {
	var addr = prompt ("flag");
	if (addr) {
		if (addr=="-") {
			r2.cmd("f"+addr);
		} else {
			r2.cmd("f "+addr);
		}
		update();
	}
}

function block() {
	var size = prompt ("block");
	if (size && size.trim()) {
		r2.cmd("b "+size);
		update();
	}
}

function flagsize() {
	var size = prompt ("size");
	if (size && size.trim()) {
		r2.cmd("fl $$ "+size);
		update();
	}
}

function seek(x) {
	if (x === undefined) {
		var addr = prompt ("address");
	} else {
		var addr = x;
	}
	if (addr && addr.trim() != "") {
		r2.cmd("s "+addr);
		if (lastView == 'px') {
			panelHexdump();
		} else {
			panelDisasm();
		}
		document.getElementById('content').scrollTop = 0;
		update();
	}
}

function analyze() {
	r2.cmd("af", function() {
		panelDisasm();
	});
}

function uiCheckList(grp,id,label) {
	return '<li> <label for="'+grp+'" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect"> <input type="checkbox" id="'+id+'" class="mdl-checkbox__input" /><span class="mdl-checkbox__label">'+label+'</span> </label> </li>';
}

function notes() {
	var c = document.getElementById("content");
	document.getElementById('title').innerHTML = 'Notes';
	var out = '<br />'+uiButton('javascript:panelComments()', '&lt; Comments');
	out += '<br /><br /><textarea rows=32 style="width:100%"></textarea>';
	c.innerHTML = out;
}

function setFlagspace(fs) {
	if (!fs) fs = prompt("name");
	if (!fs) return;
	r2.cmd ("fs "+fs, function() {
		flagspaces();
	});
}

function renameFlagspace(fs) {
	if (!fs) fs = prompt("name");
	if (!fs) return;
	r2.cmd ("fsr "+fs, function() {
		flagspaces();
	});
}

function delFlagspace(fs) {
	if (!fs) fs = ".";
	if (!fs) return;
	r2.cmd ("fs-"+fs, function() {
		flagspaces();
	});
}

function setNullFlagspace(fs) {
	var update = fs? panelFlags: flagspaces;
	r2.cmd ("fs *", function() {
		flagspaces();
	});
}

function flagspaces() {
	var c = document.getElementById("content");
	document.getElementById('title').innerHTML = 'Flag Spaces';
	c.innerHTML = '<br />&nbsp;'+uiRoundButton('javascript:panelFlags()', 'undo');
	c.innerHTML += '&nbsp;'+uiButton('javascript:setNullFlagspace()', 'Deselect');
	c.innerHTML += '&nbsp;'+uiButton('javascript:setFlagspace()', 'Add');
	c.innerHTML += '&nbsp;'+uiButton('javascript:delFlagspace()', 'Delete');
	c.innerHTML += '&nbsp;'+uiButton('javascript:renameFlagspace()', 'Rename');
	c.innerHTML += '<br /><br />';
	r2.cmd ("fs", function (d) {
		var lines = d.split(/\n/);
		var body = uiTableBegin (['+Flags', 'Flagspace']);
		for (var i in lines) {
			var line = lines[i].split(/ +/);
			if (line.length >= 4) {
				var selected = line[2].indexOf('.') == -1;
				var a = "";
				a += '<a href="javascript:setFlagspace(\''+line[3]+'\')">';
				if (selected) a+= "<font color='red'>"+line[3]+"</font>";
				else a+= line[3];
				a+= "</a>";
				body += uiTableRow ([
					'+'+line[1], a
				]);
			}
		}
		body += uiTableEnd();
		c.innerHTML += body;
	});
}

function analyzeSymbols() {
	r2.cmd('aa',function() {
		update();
	});
}
function analyzeRefs() {
	r2.cmd('aar',function() {
		update();
	});
}
function analyzeCalls() {
	r2.cmd('aac',function() {
		update();
	});
}
function analyzeFunction() {
	r2.cmd('af',function() {
		update();
	});
}
function analyzeNames() {
	r2.cmd('.afna @@ fcn.*',function() {
		update();
	});
}

function smallDisasm() {
	r2.cmd ("e asm.bytes=false");
	r2.cmd ("e asm.lines=false");
	r2.cmd ("e asm.cmtright=false");
}

function mediumDisasm() {
	r2.cmd ("e asm.bytes=false");
	r2.cmd ("e asm.lines=true");
	r2.cmd ("e asm.lineswidth=8");
	r2.cmd ("e asm.cmtright=false");
}

function largeDisasm() {
	r2.cmd ("e asm.bytes=true");
	r2.cmd ("e asm.lines=true");
	r2.cmd ("e asm.lineswidth=12");
	r2.cmd ("e asm.cmtright=true");
}

function configPseudo() {
	r2.cmd("e asm.pseudo=1");
	r2.cmd("e asm.syntax=intel");
}

function configOpcodes() {
	r2.cmd("e asm.pseudo=0");
	r2.cmd("e asm.syntax=intel");
}

function configATT() {
	r2.cmd("e asm.pseudo=0");
	r2.cmd("e asm.syntax=att");
}

function panelAbout() {
	alert ("radare2 material webui\n by --pancake @ 2015");
}

function configColorDefault() {
	r2.cmd ('ecd', function() {
		update();
	});
}
function configColorRandom() {
	r2.cmd ('ecr', function() {
		update();
	});
}

function configColorTheme(theme) {
	r2.cmd ('eco '+theme, function() {
		update();
	});
}

function configPA() {
	r2.cmd("e io.va=false");
}

function configVA() {
	r2.cmd("e io.va=true");
}

function configDebug() {
	r2.cmd("e io.va=true");
	r2.cmd("e io.debug=true");
}

function configArch(name) { r2.cmd("e asm.arch="+name); }
function configBits8() { r2.cmd("e asm.bits=8"); }
function configBits16() { r2.cmd("e asm.bits=16"); }
function configBits32() { r2.cmd("e asm.bits=32"); }
function configBits64() { r2.cmd("e asm.bits=64"); }
function configColorTrue() { inColor = true; }
function configColorFalse() { inColor = false; }

var comboId = 0;

function uiCombo(d) {
	var fun_name = "combo"+(++comboId);
	var fun = fun_name +' = function(e) {';
	fun += ' var sel = document.getElementById("opt_'+fun_name+'");';
	fun += ' var opt = sel.options[sel.selectedIndex].value;'
	fun += ' switch (opt) {';
	for (var a in d) {
		fun += 'case "'+d[a].name+'": '+d[a].js+'('+d[a].name+');break;';
	}
	fun += '}}';
	// CSP violation here
	eval (fun);
	var out = '<select id="opt_'+fun_name+'" onchange="'+fun_name+'()">';
	for (var a in d) {
		var def = (d[a].default)? " default": ""
		out += '<option'+def+'>'+d[a].name+'</option>';
	}
	out += '</select>';
	return out;
}

function uiSwitch(d) {
// TODO: not yet done
	var out = ''+d+
'<label class="mdl-switch mdl-js-switch mdl-js-ripple-effect" for="switch-1">'+
'<input type="checkbox" id="switch-1" class="mdl-switch__input" checked />'+
'<span class="mdl-switch__label"></span>'+
'</label>';
	return out;
}

function uiBlock(d) {
	var out = '<br /><div class="mdl-card__supporting-text mdl-shadow--2dp mdl-color-text--blue-grey-50 mdl-cell" style="display:inline-block;margin:5px;color:black !important;background-color:white !important">';
	out += '<h3 style="color:black">'+d.name+'</h3>';
	for (var i in d.blocks) {
		var D = d.blocks[i];
		out += '<br />'+D.name+': ';
		out += uiCombo(D.buttons);
	}
	out += '</div>';
	return out;
}

function panelSettings() {
	update = panelSettings;
	var out = '';
	document.getElementById('title').innerHTML = 'Settings';
	var c = document.getElementById("content");

	c.style.backgroundColor = '#f0f0f0';
	out += uiBlock({ name: 'Platform', blocks: [
	     { name: "Arch", buttons: [
			{ name: "x86", js: 'configArch', default:true },
			{ name: "arm", js: 'configArch' },
			{ name: "mips", js: 'configArch' },
			{ name: "java", js: 'configArch' },
			{ name: "dalvik", js: 'configArch' },
			{ name: "6502", js: 'configArch' },
			{ name: "8051", js: 'configArch' },
			{ name: "h8300", js: 'configArch' },
			{ name: "hppa", js: 'configArch' },
			{ name: "i4004", js: 'configArch' },
			{ name: "i8008", js: 'configArch' },
			{ name: "lh5801", js: 'configArch' },
			{ name: "lm32", js: 'configArch' },
			{ name: "m68k", js: 'configArch' },
			{ name: "malbolge", js: 'configArch' },
			{ name: "mcs96", js: 'configArch' },
			{ name: "msp430", js: 'configArch' },
			{ name: "nios2", js: 'configArch' },
			{ name: "ppc", js: 'configArch' },
			{ name: "rar", js: 'configArch' },
			{ name: "sh", js: 'configArch' },
			{ name: "snes", js: 'configArch' },
			{ name: "sparc", js: 'configArch' },
			{ name: "spc700", js: 'configArch' },
			{ name: "sysz", js: 'configArch' },
			{ name: "tms320", js: 'configArch' },
			{ name: "v810", js: 'configArch' },
			{ name: "v850", js: 'configArch' },
			{ name: "ws", js: 'configArch' },
			{ name: "xcore", js: 'configArch' },
			{ name: "prospeller", js: 'configArch' },
			{ name: "gb", js: 'configArch' },
			{ name: "z80", js: 'configArch' },
			{ name: "arc", js: 'configArch' },
			{ name: "avr", js: 'configArch' },
			{ name: "bf", js: 'configArch' },
			{ name: "cr16", js: 'configArch' },
			{ name: "cris", js: 'configArch' },
			{ name: "csr", js: 'configArch' },
			{ name: "dcpu16", js: 'configArch' },
			{ name: "ebc", js: 'configArch' },
		]}, 
	     { name: "Bits", buttons: [
			{ name: "64", js: 'configBits64' },
			{ name: "32", js: 'configBits32', default:true },
			{ name: "16", js: 'configBits16' },
			{ name: "8", js: 'configBits8' },
		]},
	     { name: "OS", buttons: [
			{ name: "Linux", js: 'configOS_LIN', default:true },
			{ name: "Windows", js: 'configOS_W32' },
			{ name: "OSX", js: 'configOS_OSX' },
		]},
	    ]
	});
	out += uiBlock({ name: 'Disassembly', blocks: [
		{
		       name: 'Size', buttons: [
			{ name: "S", js: 'smallDisasm' },
			{ name: "M", js: 'mediumDisasm' },
			{ name: "L", js: 'largeDisasm' }
		       ]},
		{
		       name: 'Decoding', buttons: [
			{ name: 'Pseudo', js: 'configPseudo' },
			{ name: 'Opcodes', js: 'configOpcodes' },
			{ name: 'ATT', js: 'configATT' }
		       ]},
		       {
		    name: 'Colors', buttons: [
		     { name: "Yes", js: 'configColorTrue', default:true },
		     { name: "No", js: 'configColorFalse' },
		    ]
	     }, {
		       name: 'Theme', buttons: [
			{ name: 'Default', js: 'configColorDefault' },
			{ name: 'Random', js: 'configColorRandom' },
			{ name: 'Solarized', js: 'configColorTheme("solarized")' },
			{ name: 'Ogray', js: 'configColorTheme("ogray")' },
			{ name: 'Twilight', js: 'configColorTheme("twilight")' },
			{ name: 'Rasta', js: 'configColorTheme("rasta")' },
			{ name: 'Tango', js: 'configColorTheme("tango")' },
			{ name: 'White', js: 'configColorTheme("white")' },
			]}
					]
	});
	out += uiBlock({ name: 'Core/IO', blocks: [
		{
		    name: 'Mode', buttons: [
		     { name: "PA", js: 'configPA' },
		     { name: "VA", js: 'configVA' },
		     { name: "Debug", js: 'configDebug' }
		    ]
		},
]});
	out += uiBlock({ name: 'Analysis', blocks: [
		{
		    name: 'HasNext', buttons: [
		     { name: "Yes", js: 'configAnalHasnextTrue', default: true },
		     { name: "No", js: 'configAnalHasnextFalse' },
		    ]
	     	},{
		    name: 'Skip Nops', buttons: [
		     { name: "Yes", js: 'configAnalNopskipTrue', default: true },
		     { name: "No", js: 'configAnalNopskipFalse' },
		    ]
		},{
		    name: 'NonCode', buttons: [
		     { name: "Yes", js: 'configAnalNoncodeTrue' },
		     { name: "No", js: 'configAnalNoncodeFalse', default: true },
		    ]
		}
		]});


	c.innerHTML = out;
}

function printHeaderPanel(title, cmd, grep) {
	update = panelFunctions;
	document.getElementById('title').innerHTML = title;
	var c = document.getElementById("content");
	c.style.backgroundColor = '#f0f0f0';
	c.innerHTML = "<br />";
	c.innerHTML += uiButton('javascript:panelHeaders()', 'Headers');
	c.innerHTML += uiButton('javascript:panelSymbols()', 'Symbols');
	c.innerHTML += uiButton('javascript:panelImports()', 'Imports');
	c.innerHTML += uiButton('javascript:panelRelocs()', 'Relocs');
	c.innerHTML += uiButton('javascript:panelSections()', 'Sections');
	c.innerHTML += uiButton('javascript:panelSdb()', 'Sdb');
	if (grep) {
		cmd += "~" + grep;
	}
	r2.cmd (cmd, function (d) {
		var color = inColor? "white": "black";
		c.innerHTML += "<pre style='font-family:Console,Courier New,monospace' style='color:"+color+" !important'>"+d+"<pre>";
	});
}

function panelSdb() {
	printHeaderPanel ('SDB', 'k bin/cur/***');
}
function panelSections() {
	printHeaderPanel ('Imports', 'iSq');
}
function panelImports() {
	printHeaderPanel ('Imports', 'isq', ' imp.');
}

function panelRelocs() {
	printHeaderPanel ('Relocs', 'ir');
}

function panelSymbols() {
	printHeaderPanel ('Imports', 'isq', '!imp');
}

function panelHeaders() {
	printHeaderPanel ('Headers', 'i');
}

function panelFunctions() {
	update = panelFunctions;
	document.getElementById('title').innerHTML = 'Functions';
	var c = document.getElementById("content");
	c.style.backgroundColor = '#f0f0f0';
	var body = "<br />";
	body += uiButton('javascript:analyzeSymbols()', 'Symbols');
	body += uiButton('javascript:analyzeCalls()', 'Calls');
	body += uiButton('javascript:analyzeFunction()', 'Function');
	body += uiButton('javascript:analyzeRefs()', 'Refs');
	body += uiButton('javascript:analyzeNames()', 'AutoName');
	body += '<br /><br />';
	c.innerHTML = body;
	r2.cmd("e scr.utf8=false");
	r2.cmd ("afl", function (d) {
		//var dis = clickableOffsets (d);
		//c.innerHTML += "<pre style='font-family:Console,Courier New,monospace' style='color:white !important'>"+dis+"<pre>";
		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		var body = uiTableBegin (['+Address', 'Name', '+Size', '+CC']);
		for (var i in lines) {
			var line = lines[i].split(/ +/);
			if (line.length >= 3)
				body += uiTableRow ([
					'+'+line[0],
					'+'+line[3],
					'+'+line[1],
					line[2]
				]);
		}
		body += uiTableEnd();
		c.innerHTML += body;
	});
}

function runCommand(text) {
	if (!text)
		text = document.getElementById('input').value;
	r2.cmd (text, function (d) {
		document.getElementById('output').innerHTML = '\n'+d;
	});
}

function consoleKey(e) {
	var inp = document.getElementById('input');
	if (!e) {
		inp.onkeypress = consoleKey;
	} else {
		if (e.keyCode == 13) {
			runCommand (inp.value);
			inp.value = '';
		}
	}
}

function singlePanel() {
	window.top.location.href = "/m/";
}
function hSplit() {
	location.href = "/m/hsplit";
}
function vSplit() {
	location.href = "/m/vsplit";
}

function panelConsole() {
	update = panelConsole;
	document.getElementById('title').innerHTML = 'Console';
	var c = document.getElementById("content");
	c.innerHTML = "<br />";
	if (inColor) {
		c.style.backgroundColor = "#202020";
		c.innerHTML += "<input style='position:absolute;padding-left:10px;top:3.5em;height:1.8em;color:white' onkeypress='consoleKey()' class='mdl-card--expand mdl-textfield__input' id='input'/>";
		//c.innerHTML += uiButton('javascript:runCommand()', 'Run');
		c.innerHTML += "<div id='output' class='pre' style='color:white !important'><div>";
	} else {
		c.style.backgroundColor = "#f0f0f0";
		c.innerHTML += "<input style='color:black' onkeypress='consoleKey()' class='mdl-card--expand mdl-textfield__input' id='input'/>";
		c.innerHTML += uiButton('javascript:runCommand()', 'Run');
		c.innerHTML += "<div id='output' class='pre' style='color:black!important'><div>";
	}
}

function searchKey(e) {
	var inp = document.getElementById('search_input');
	if (!e) {
		inp.onkeypress = searchKey;
	} else {
		if (e.keyCode == 13) {
			runSearch (inp.value);
			inp.value = '';
		}
	}
}
function runSearchMagic(text) {
	r2.cmd ('/m', function (d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}
function runSearchCode(text) {
	if (!text) text = document.getElementById('search_input').value;
	r2.cmd ('"/c '+text+'"', function (d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}
function runSearchString(text) {
	if (!text) text = document.getElementById('search_input').value;
	r2.cmd ('/ '+text, function (d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}
function runSearchROP(text) {
	if (!text) text = document.getElementById('search_input').value;
	r2.cmd ('"/R '+text+'"', function (d) {
		document.getElementById('search_output').innerHTML = clickableOffsets(d);
	});
}

function runSearch(text) {
	if (!text)
		text = document.getElementById('search_input').value;
	if (text[0]=='"') {
		r2.cmd ('"/ '+text+'"', function (d) {
			document.getElementById('search_output').innerHTML = clickableOffsets(d);
		});
	} else {
		r2.cmd ('"/x '+text+'"', function (d) {
			document.getElementById('search_output').innerHTML = clickableOffsets(d);
		});
	}
}

function indentScript() {
	var str = document.getElementById('script').value;
	var indented = js_beautify (str);
	document.getElementById('script').value = indented;
	localStorage['script'] = indented;
}

function runScript() {
	var str = document.getElementById('script').value;
	localStorage['script'] = str;
	document.getElementById('scriptOutput').innerHTML = '';
	try {
		var msg = "\"use strict\";"+
		"function log(x) { var a = "+
		"document.getElementById('scriptOutput'); "+
		"if (a) a.innerHTML += x + '\\n'; }\n";
		// CSP violation here
		eval (msg + str);
	} catch (e) {
		alert (e);
	}
}

var foo = "";
function toggleScriptOutput() {
	var o = document.getElementById('scriptOutput');
	if (o) {
		if (foo == "") {
			foo = o.innerHTML;
			o.innerHTML = "";
		} else {
			o.innerHTML = foo;
			foo = "";
		}
	}
}

function panelScript() {
	update = panelScript;
	document.getElementById('title').innerHTML = 'Script';
	var c = document.getElementById("content");
	c.style.backgroundColor = "#f0f0f0";
	var localScript = localStorage.getItem('script');
	var out = '<br />'+uiButton('javascript:runScript()', 'Run');
	out += '&nbsp;'+uiButton('javascript:indentScript()', 'Indent');
	out += '&nbsp;'+uiButton('javascript:toggleScriptOutput()', 'Output');
	out += '<br /><div class="output" id="scriptOutput"></div><br />';
	out += '<textarea rows=32 id="script" class="pre" style="width:100%">';
	if (!localScript) {
		localScript = 'r2.cmd("?V", log);';
	}
	out += localScript + '</textarea>';
	c.innerHTML = out;
}

function panelSearch() {
	update = panelSearch;
	document.getElementById('title').innerHTML = 'Search';
	var c = document.getElementById("content");
	c.style.backgroundColor = "#f0f0f0";
	var out = "<br />";
	out += "<input style='z-index:9999;background-color:white !important;position:absolute;padding-left:10px;top:3.5em;height:1.8em;color:white' onkeypress='searchKey()' class='mdl-card--expand mdl-textfield__input' id='search_input'/>";
	out+='<br />';
	out+=uiButton('javascript:runSearch()', 'Hex');
	out+=uiButton('javascript:runSearchString()', 'String');
	out+=uiButton('javascript:runSearchCode()', 'Code');
	out+=uiButton('javascript:runSearchROP()', 'ROP');
	out+=uiButton('javascript:runSearchMagic()', 'Magic');
	out+='<br /><br />';
	out += "<div id='search_output' class='pre' style='color:black!important'><div>";
	c.innerHTML = out;
}

function uiTableBegin(cols) {
	var out = '';
	out += '<table style="margin-left:10px" class="mdl-data-table mdl-js-data-table mdl-data-table--selectable mdl-shadow--2dp">';
	//out += '<table class="mdl-data-table mdl-js-data-table mdl-data-table--selectable">';

	out += '  <thead> <tr>';

	var type;
	for (var i in cols) {
		var col = cols[i];
		if (col[0] == '+') {
			col = col.substring(1);
			type = '';
		} else {
			type = ' class="mdl-data-table__cell--non-numeric"';
		}
		out += "<th"+type+">"+col+"</th>";
	}
	out += '</tr> </thead> <tbody>';
	return out;
}

function uiTableRow(cols) {
	var out = '<tr>';
	for (var i in cols) {
		var col = cols[i];
		if (!col) continue;
		if (col[0] == '+') {
			col = clickableOffsets (col.substring(1));
			type = '';
		} else {
			type = ' class="mdl-data-table__cell--non-numeric"';
		}
		out += '<td'+type+'>'+col+'</td>';
	}
	return out + '</tr>';
}

function uiTableEnd() {
	return "</tbody> </table>";
}

function panelFlags() {
	update = panelFlags;
	document.getElementById('title').innerHTML = 'Flags';
	var c = document.getElementById("content");
	c.style.backgroundColor = "#f0f0f0";
	c.innerHTML = "<br />";
	c.innerHTML += uiButton('javascript:flagspaces()', 'Spaces');
	c.innerHTML += "<br /><br />";
	r2.cmd ("f", function (d) {
		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		var body = uiTableBegin (['+Offset', '+Size', 'Name']);
		for (var i in lines) {
			var line = lines[i].split(/ /);
			if (line.length >= 3)
				body += uiTableRow ([
					'+'+line[0],
					'+'+line[1],
					line[2]
				]);
		}
		body += uiTableEnd();
		c.innerHTML += body;
	});
}

function panelComments() {
	update = panelComments;
	document.getElementById('title').innerHTML = 'Comments';
	var c = document.getElementById("content");
	c.style.backgroundColor = "#f0f0f0";
	c.innerHTML = "<br />";
	c.innerHTML += uiButton('javascript:notes()', 'Notes');
	c.innerHTML += "<br /><br />";
	r2.cmd ("CC", function (d) {
		var lines = d.split(/\n/); //clickableOffsets (d).split (/\n/);
		var body = uiTableBegin (['+Offset', 'Comment']);
		for (var i in lines) {
			var line = lines[i].split(/ (.+)?/);
			if (line.length >= 2)
				body += uiTableRow ([
					'+'+line[0],
					'+'+line[1]
				]);
		}
		body += uiTableEnd();
		c.innerHTML += body;
	});
}

function up() {
	r2.cmd ("s--");
	update();
}

function down() {
	r2.cmd ("s++");
	update();
}

function panelHexdump() {
	document.getElementById('content').scrollTop = 0;
	update = panelHexdump;
	lastView = 'px';
	var c = document.getElementById("content");
	document.getElementById('title').innerHTML = 'Hexdump';
	if (inColor) {
		c.style.backgroundColor = "#202020";
	}
	var out = "<br />";
	out += uiRoundButton('javascript:up()', 'keyboard_arrow_up');
	out += uiRoundButton('javascript:down()', 'keyboard_arrow_down');
	out += '&nbsp;';
	out += uiButton('javascript:comment()', 'Comment');
	out += uiButton('javascript:write()', 'Write');
	out += uiButton('javascript:flag()', 'Flag');
	out += uiButton('javascript:flagsize()', 'Size');
	out += uiButton('javascript:block()', 'Block');
	c.innerHTML = out;
	var tail = inColor? '@e:scr.color=1,scr.html=1': '';
	r2.cmd ("pxa"+tail, function (d) {
		var color = inColor? "white": "black";
		d = clickableOffsets (d);
		c.innerHTML += "<pre style='color:"+color+"!important'>"+d+"<pre>";
	});
}

function uiRoundButton(a, b) {
	var out = '';
	out += '<button onclick='+a+' class="mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect">';
	out += '<i class="material-icons">'+b+'</i>';
	out += '</button>';
	return out;
}

function panelDisasm() {
	document.getElementById('content').scrollTop = 0;
	update = panelDisasm;
	lastView = panelDisasm;
	var c = document.getElementById("content");
	document.getElementById('title').innerHTML = 'Disassembly';
	if (inColor) {
		c.style.backgroundColor = "#202020";
	}
	var out = "<br />";
	out += uiRoundButton('javascript:up()', 'keyboard_arrow_up');
	out += uiRoundButton('javascript:down()', 'keyboard_arrow_down');
	out += '&nbsp;';
	out += uiButton('javascript:analyze()', 'Analyze');
	out += uiButton('javascript:comment()', 'Comment');
	out += uiButton('javascript:info()', 'Info');
	out += uiButton('javascript:rename()', 'Rename');
	out += uiButton('javascript:write()', 'Write');
	c.innerHTML = out;
	c.style['font-size'] = '12px';
	c.style.overflow = 'scroll';
	var tail = '';
	if (inColor) {
		tail = '@e:scr.color=1,scr.html=1';
	}
	r2.cmd ("pd 128"+tail, function (d) {
		var dis = clickableOffsets (d);
		c.innerHTML += "<pre style='font-family:Console,Courier New,monospace;color:grey'>"+dis+"<pre>";
	});
}

var nativeDebugger = false;

function srpc() {
	r2.cmd ("sr pc", update);
}
function stepi() {
	if (nativeDebugger) {
		r2.cmd ("ds", update);
	} else {
		r2.cmd ("aes", update);
	}
}
function cont() {
	if (nativeDebugger) {
		r2.cmd ("dc", update);
	} else {
		r2.cmd ("aec", update);
	}
}
function setbp() {
	r2.cmd ("db $$", update);
}
function setreg() {
	var expr = prompt ("comment");
	if (expr != '') {
		if (nativeDebugger) {
			r2.cmd ("dr "+expr+";.dr*", update);
		} else {
			r2.cmd ("aer "+expr+";.ar*", update);
		}
	}
}

function panelDebug() {
	r2.cmd("e cfg.debug", function (x) {
		nativeDebugger = (x.trim() == 'true');
	});
	document.getElementById('content').scrollTop = 0;
	update = panelDebug;
	lastView = panelDebug;
	var c = document.getElementById("content");
	document.getElementById('title').innerHTML = 'Debugger';
	if (inColor) {
		c.style.backgroundColor = "#202020";
	}
	var out = "<br />";
	out += uiRoundButton('javascript:up()', 'keyboard_arrow_up');
	out += uiRoundButton('javascript:down()', 'keyboard_arrow_down');
	out += '&nbsp;';
	out += uiButton('javascript:srpc()', 'PC');
	out += uiButton('javascript:stepi()', 'Step');
	out += uiButton('javascript:cont()', 'Cont');
	out += uiButton('javascript:setbp()', 'BP');
	out += uiButton('javascript:setreg()', 'REG');
	c.innerHTML = out;
	var tail = '';
	if (inColor) {
		tail = '@e:scr.color=1,scr.html=1';
	}
	// stack
	if (nativeDebugger) {
		var rcmd = "dr";
	} else {
		var rcmd = "ar";
	}
        r2.cmd ("f cur;."+rcmd+"*;sr sp;px 64", function (d) {
                var dis = clickableOffsets (d);
                c.innerHTML += "<pre style='font-family:Console,Courier New,monospace;color:grey'>"+dis+"<pre>";
        });
	r2.cmd (rcmd+"=;s cur;f-cur;pd 128"+tail, function (d) {
		var dis = clickableOffsets (d);
		c.innerHTML += "<pre style='font-family:Console,Courier New,monospace;color:grey'>"+dis+"<pre>";
	});
}

function saveProject() {
	r2.cmd ("Ps", function() {
		alert ("Project saved");
	});
}
function deleteProject() {
	alert ("Project deleted");
	location.href = "open.html";
}
function closeProject() {
	alert ("Project closed");
	location.href = "open.html";
}
function rename() {
	var name= prompt ("name");
	if (name && name.trim() != "") {
		r2.cmd("afn "+name);
		r2.cmd("f "+name);
		update();
	}
}
function info() {
	var c = document.getElementById('content');
	var color = inColor? "white": "black";
	document.getElementById('title').innerHTML = 'Info';
	var out = "<br />"; //Version: "+d;
	out += uiRoundButton('javascript:panelDisasm()', 'undo');
	out += '&nbsp;';
	out += uiButton ('javascript:pdtext()', 'Full');
	out += uiButton ('javascript:pdf()', 'Func');
	out += uiButton ('javascript:graph()', 'Graph');
	out += uiButton ('javascript:blocks()', 'Blocks');
	out += uiButton ('javascript:decompile()', 'Decompile');
	c.innerHTML = out;
	r2.cmd ("afi", function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier,monospace;color:"+color+"'>"+d+"<pre>";
	});
}

function blocks() {
	document.getElementById('title').innerHTML = 'Blocks';
	var c = document.getElementById('content');
	c.style['overflow'] = 'none';
	var color = inColor? "white": "black";
	c.innerHTML = "<br />";
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor? '@e:scr.color=1,scr.html=1': '';
	r2.cmd ("pdr"+tail, function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier,monospace;color:"+color+"'>"+d+"<pre>";
	});
}

function pdtext() {
	document.getElementById('title').innerHTML = 'Function';
	var c = document.getElementById('content');
	c.style['overflow'] = 'none';
	var color = inColor? "white": "black";
	c.innerHTML = "<br />";
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor? '@e:scr.color=1,scr.html=1,asm.lineswidth=0': '@e:asm.lineswidth=0';
	r2.cmd("e scr.color=1;s entry0;s $S;pD $SS;e scr.color=0", function(d) {
		d = clickableOffsets (d);
		c.innerHTML += "<pre style='font-family:Console,Courier,monospace;color:"+color+"'>"+d+"<pre>";
	});
}

function pdf() {
	document.getElementById('title').innerHTML = 'Function';
	var c = document.getElementById('content');
	c.style['overflow'] = 'none';
	var color = inColor? "white": "black";
	c.innerHTML = "<br />";
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor? '@e:scr.color=1,scr.html=1,asm.lineswidth=0': '@e:asm.lineswidth=0';
	r2.cmd ("pdf"+tail, function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier,monospace;color:"+color+"'>"+d+"<pre>";
	});
}

function decompile() {
	document.getElementById('title').innerHTML = 'Decompile';
	var c = document.getElementById('content');
	c.style['overflow'] = 'none';
	var color = inColor? "white": "black";
	c.innerHTML = "<br />";
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	var tail = inColor? '@e:scr.color=1,scr.html=1': '';
	r2.cmd ("pdc"+tail, function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier,monospace;color:"+color+"'>"+d+"<pre>";
	});
}

function graph() {
	document.getElementById('title').innerHTML = 'Graph';
	var c = document.getElementById('content');
	c.style['overflow'] = 'auto';
	var color = inColor? "white": "black";
	c.innerHTML = '<br />&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a>';
	var tail = inColor? '@e:scr.color=1,scr.html=1': '';
	r2.cmd ("agf"+tail, function (d) {
		d = clickableOffsets(d);
		c.innerHTML += "<pre style='font-family:Console,Courier New,monospace;color:"+color+"'>"+d+"<pre>";
	});
}

//-------------

    Array.prototype.forEach.call(document.querySelectorAll('.mdl-card__media'), function(el) {
      var link = el.querySelector('a');
      if(!link) {
        return;
      }
      var target = link.getAttribute('href');
      if(!target) {
        return;
      }
      el.addEventListener('click', function() {
        location.href = target;
      });
    });

function updateFortune() {
	r2.cmd ("fo", function(d) {
		document.getElementById('fortune').innerHTML = d;
	});
}
function updateInfo() {
	r2.cmd ("i", function(d) {
		var lines = d.split(/\n/g);
		var lines1 = lines.slice (0,lines.length/2);
		var lines2 = lines.slice (lines.length/2);
		var body = "";

		body += "<table style='width:100%'><tr><td>";
		for (var i in lines1) {
			var line = lines1[i].split(/ (.+)?/);
			if (line.length>=2)
				body += "<b>"+line[0]+"</b> "+line[1]+"<br/>";
		}
		body += "</td><td>";
		for (var i in lines2) {
			var line = lines2[i].split(/ (.+)?/);
			if (line.length>=2)
				body += "<b>"+line[0]+"</b> "+line[1]+"<br/>";
		}
		body += "</td></tr></table>";
		document.getElementById('info').innerHTML = body;
	});
}

function onClick(a,b) {
	var h = document.getElementById(a);
	if (h) {
		h.addEventListener('click', function() {
			b();
		});
	} else {
		console.error('onclick-error', a);
	}
}

updateInfo();

function panelHelp() {
	alert ("TODO");
}

var twice = false;
function ready() {
	if (twice) {
		return;
	}
	twice = true;
	updateFortune();
	updateInfo();

	/* left menu */
	onClick('menu_headers', panelHeaders);
	onClick('menu_disasm', panelDisasm);
	onClick('menu_debug', panelDebug);
	onClick('menu_hexdump', panelHexdump);
	onClick('menu_functions', panelFunctions);
	onClick('menu_flags', panelFlags);
	onClick('menu_search', panelSearch);
	onClick('menu_comments', panelComments);
	onClick('menu_script', panelScript);
	onClick('menu_help', panelHelp);

	/* left sub-menu */
	onClick('menu_project_save', saveProject);
	onClick('menu_project_delete', deleteProject);
	onClick('menu_project_close', closeProject);

	/* right menu */
	onClick('menu_seek', seek);
	onClick('menu_console', panelConsole);
	onClick('menu_settings', panelSettings);
	onClick('menu_about', panelAbout);
	onClick('menu_mail', function() {
		window.location = 'mailto:pancake@nopcode.org';
        });
}
window.onload = ready

document.addEventListener( "DOMContentLoaded", ready, false )

document.body.onkeypress = function(e) {
	if (e.ctrlKey) {
		const keys = [
			panelConsole,
			panelDisasm,
			panelDebug,
			panelHexdump,
			panelFunctions,
			panelFlags,
			panelHeaders,
			panelSettings,
			panelSearch
		];
		if (e.charCode == "o".charCodeAt(0)) {
			seek();
		}
		var k = e.charCode - 0x30;
		if (k>=0 && k< keys.length) {
			var fn = keys[k];
			if (fn) fn();
		}
	}
}
