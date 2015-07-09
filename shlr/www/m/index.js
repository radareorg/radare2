
var update = function() {/* nop */}
var inColor = true;

function uiButton(href,label,type) {
if (type=='active') {
	return '&nbsp;<a href="'+href.replace(/"/g,"'")+'" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast" style="background-color:#f04040 !important">'+label+'</a>';
}
	return '&nbsp;<a href="'+href.replace(/"/g,"'")+'" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">'+label+'</a>';
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

function seek() {
	var addr = prompt ("address");
	if (addr && addr.trim() != "") {
		r2.cmd("s "+addr);
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
	out += '<br /><br /><textarea style="width:100%"></textarea>';
	c.innerHTML = out;
}

function flagspaces() {
	var c = document.getElementById("content");
	document.getElementById('title').innerHTML = 'Flag Spaces';
	c.innerHTML += '<br /><br />'+uiButton('javascript:flagspaces()', 'Flags');
	if (inColor) {
		r2.cmd("e scr.color=true");
		r2.cmd("e scr.html=true");
	}
	r2.cmd("e scr.utf8=false");
	r2.cmd ("fs", function (d) {
// TODO: show in checklist
		//c.innerHTML += "<pre style='font-family:Console,Courier' color=white>"+d+"<pre>";
		var out = "<br />"+uiButton('javascript:panelFlags()', '&lt; Flags');
		var list = d.split("\n");
		out += "<ul>";
		for (var i in list) {
			var list2 = list[i].trim().split(/ +/g);
			if (list2.length<2) continue;
			//var line = list[i].trim();
			var label = list2[3] + ' ('+list2[1]+')';
			out += uiCheckList('fs','chk'+i,label);
		}
		out +"</ul>";
		c.innerHTML = out;
	});
}

function analyzeSymbols() {
	r2.cmd('aa',function() {
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

function configArchARM() { r2.cmd("e asm.arch=arm"); }
function configArchX86() { r2.cmd("e asm.arch=x86"); }
function configArchMIPS() { r2.cmd("e asm.arch=mips"); }
function configArchDALVIK() { r2.cmd("e asm.arch=dalvik"); }
function configArchJAVA() { r2.cmd("e asm.arch=java"); }
function configBits8() { r2.cmd("e asm.bits=8"); }
function configBits16() { r2.cmd("e asm.bits=16"); }
function configBits32() { r2.cmd("e asm.bits=32"); }
function configBits64() { r2.cmd("e asm.bits=64"); }
function configColorTrue() { inColor = true; r2.cmd("e scr.color=true"); }
function configColorFalse() { inColor = false; r2.cmd("e scr.color=false"); }

function uiBlock(d) {
	var out = '<br /><div class="mdl-card__supporting-text mdl-color-text--blue-grey-50" style="color:black !important;background-color:white !important">';
	out += '<h3 style="color:black">'+d.name+'</h3>';
	for (var i in d.blocks) {
		var D = d.blocks[i];
		out += '<br />'+D.name+': ';
		for (var b in D.buttons) {
			var B = D.buttons[b];
if (B.default) {
			out += uiButton('javascript:'+B.js+'()', B.name, 'active');
} else {
			out += uiButton('javascript:'+B.js+'()', B.name);
}
		}
	}
	out += '</div><br />';
	return out;
}

function panelSettings() {
	update = panelSettings;
	var out = '';
	document.getElementById('title').innerHTML = 'Settings';
	var c = document.getElementById("content");

	c.style = 'background-color: #f0f0f0 !important';
	out += uiBlock({ name: 'Platform', blocks: [
	     { name: "Arch", buttons: [
			{ name: "x86", js: 'configArchX86', default:true },
			{ name: "arm", js: 'configArchARM' },
			{ name: "mips", js: 'configArchMIPS' },
			{ name: "java", js: 'configArchJAVA' },
			{ name: "dalvik", js: 'configArchDALVIK' },
		]}, 
	     { name: "Bits", buttons: [
			{ name: "8", js: 'configBits8' },
			{ name: "16", js: 'configBits16' },
			{ name: "32", js: 'configBits32', default:true },
			{ name: "64", js: 'configBits64' },
		]},
	     { name: "OS", buttons: [
			{ name: "Linux", js: 'configOS_LIN', default:true },
			{ name: "Windows", js: 'configOS_W32' },
			{ name: "OSX", js: 'configOS_OSX' },
		]},
	    ]
	});
	out += uiBlock({ name: 'Disassembly Options', blocks: [
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
	out += uiBlock({ name: 'Core', blocks: [
		{
		    name: 'Mode', buttons: [
		     { name: "PA", js: 'configPA' },
		     { name: "VA", js: 'configVA' },
		     { name: "Debug", js: 'configDebug' }
		    ]
		},{
		    name: 'Colors', buttons: [
		     { name: "Yes", js: 'configColorTrue', default:true },
		     { name: "No", js: 'configColorFalse' },
		    ]
	     }]});
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
	c.style = 'background-color: #f0f0f0 !important;';
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
		c.innerHTML += "<pre style='font-family:Console,Courier' style='color:"+color+" !important'>"+d+"<pre>";
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
	c.style = 'background-color: #f0f0f0 !important';
	c.innerHTML = "<br />";
	c.innerHTML += uiButton('javascript:analyzeSymbols()', 'Symbols');
	c.innerHTML += uiButton('javascript:analyzeCalls()', 'Calls');
	c.innerHTML += uiButton('javascript:analyzeFunction()', 'Function');
	c.innerHTML += uiButton('javascript:analyzeNames()', 'AutoName');
	if (inColor) {
		r2.cmd("e scr.color=true");
		r2.cmd("e scr.html=true");
	}
	r2.cmd("e scr.utf8=false");
	r2.cmd ("afl", function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier' style='color:white !important'>"+d+"<pre>";
	});
}

function runCommand() {
	var text = document.getElementById('input').value;
	r2.cmd (text, function (d) {
		document.getElementById('output').innerHTML = d;
	});
}

function panelConsole() {
	update = panelConsole;
	document.getElementById('title').innerHTML = 'Console';
	var c = document.getElementById("content");
	if (inColor) {
		c.style = 'background-color: #202020 !important';
	}
	c.innerHTML = "<br />";
	if (inColor) {
		c.innerHTML += "<input style='color:white' class='mdl-card--expand mdl-textfield__input' id='input'/>";
		c.innerHTML += uiButton('javascript:runCommand()', 'Run');
		c.innerHTML += "<pre id='output' style='color:white !important'><pre>";
		r2.cmd("e scr.color=true");
		r2.cmd("e scr.html=true");
	} else {
		c.innerHTML += "<input style='color:black' class='mdl-card--expand mdl-textfield__input' id='input'/>";
		c.innerHTML += uiButton('javascript:runCommand()', 'Run');
		c.innerHTML += "<pre id='output' style='color:black!important'><pre>";
	}
	r2.cmd("e scr.utf8=false");
}

function panelFlags() {
	update = panelFlags;
	document.getElementById('title').innerHTML = 'Flags';
	var c = document.getElementById("content");
	c.style = 'background-color: #f0f0f0 !important';
	c.innerHTML = "<br />";
	c.innerHTML += uiButton('javascript:flagspaces()', 'Spaces');
	if (inColor) {
		r2.cmd("e scr.color=true");
		r2.cmd("e scr.html=true");
	}
	r2.cmd("e scr.utf8=false");
	r2.cmd ("f", function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier' style='color:white !important'>"+d+"<pre>";
	});
}

function panelComments() {
	update = panelComments;
	document.getElementById('title').innerHTML = 'Comments';
	var c = document.getElementById("content");
	c.style = 'background-color: #f0f0f0 !important';
	c.innerHTML = "<br />";
	c.innerHTML += uiButton('javascript:notes()', 'Notes');
	if (inColor) {
		r2.cmd("e scr.color=true");
		r2.cmd("e scr.html=true");
	}
	r2.cmd("e scr.utf8=false");
	r2.cmd ("CC", function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier'>"+d+"<pre>";
	});
}

function panelHexdump() {
	update = panelHexdump;
	var c = document.getElementById("content");
	document.getElementById('title').innerHTML = 'Hexdump';
	if (inColor) {
		c.style = 'background-color: #202020 !important';
	}
	c.innerHTML = "<br />"; //Version: "+d;
	c.innerHTML += uiButton('javascript:comment()', 'Comment');
	c.innerHTML += uiButton('javascript:flag()', 'Flag');
	c.innerHTML += uiButton('javascript:flagsize()', 'Size');
	c.innerHTML += uiButton('javascript:block()', 'Block');
	if (inColor) {
		r2.cmd("e scr.color=true");
		r2.cmd("e scr.html=true");
	}
	r2.cmd("e scr.utf8=false");
	r2.cmd ("pxa", function (d) {
		var color = inColor? "white": "black";
		c.innerHTML += "<pre style='color:"+color+"!important'>"+d+"<pre>";
	});
}

function panelDisasm() {
	update = panelDisasm;
	var c = document.getElementById("content");
	document.getElementById('title').innerHTML = 'Disassembly';
	if (inColor) {
		c.style = 'background-color: #202020 !important';
	}
	var out = "<br />";
	out += '&nbsp;<a href="javascript:analyze()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">Analyze</a>';
	out += '&nbsp;<a href="javascript:comment()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">Comment</a>';
	out += '&nbsp;<a href="javascript:info()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">Info</a>';
	out += '&nbsp;<a href="javascript:rename()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">Rename</a>';
	c.innerHTML = out;
	if (inColor) {
		r2.cmd("e scr.color=true");
		r2.cmd("e scr.html=true");
	}
	r2.cmd("e scr.utf8=false");
	r2.cmd ("pd 128", function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier'>"+d+"<pre>";
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
	alert ("Project deleted");
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
	c.innerHTML = "<br />"; //Version: "+d;
	c.innerHTML += uiButton ('javascript:panelDisasm()', '&lt; disasm');
	c.innerHTML += uiButton ('javascript:graph()', 'graph');
	c.innerHTML += uiButton ('javascript:decompile()', 'decompile');
	r2.cmd ("afi", function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier;color:"+color+"'>"+d+"<pre>";
	});
}
function decompile() {
	document.getElementById('title').innerHTML = 'Decompile';
	var c = document.getElementById('content');
	c.style['overflow'] = 'none';
	var color = inColor? "white": "black";
	c.innerHTML = "<br />";
	c.innerHTML += '&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a> <h3 color=white></h3>';
	r2.cmd ("pdc", function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier;color:"+color+"'>"+d+"<pre>";
	});
}

function graph() {
	document.getElementById('title').innerHTML = 'Graph';
	var c = document.getElementById('content');
	c.style['overflow'] = 'auto';
	var color = inColor? "white": "black";
	c.innerHTML = '<br />&nbsp;<a href="javascript:panelDisasm()" class="mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--accent mdl-color-text--accent-contrast">&lt; INFO</a>';
	r2.cmd ("agf", function (d) {
		c.innerHTML += "<pre style='font-family:Console,Courier;color:"+color+"'>"+d+"<pre>";
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

