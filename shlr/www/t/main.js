
function findPos(obj) {
	var curleft = curtop = 0;
	if (obj.offsetParent) {
		curleft = obj.offsetLeft
		curtop = obj.offsetTop
		while (obj = obj.offsetParent) {
			curleft += obj.offsetLeft
			curtop += obj.offsetTop
		}
	}
	return [curleft,curtop];
}

window.onload = function() {
	var t = new Tiled ('canvas');
	var ctr = 0;
	function newHelpFrame() {
		var n = t.defname ("help");
		function newthing(name) {
			// TODO: disas_code id
			setTimeout (function () {
				r2.cmd ("fs *;f", function (x) {
					document.getElementById(name+"_flags").innerHTML="<pre>"+x+"</pre>";
				});
			}, 1);
			const hlpmsg = "This is the new and experimental tiled webui for r2\n\n"
			+"Press the 'alt' key and the following key:\n\n"
			+"  hjkl - move left,down,up,right around\n"
			+"  x    - spawn an hexdump\n"
			+"  d    - spawn an disasfm\n"
			+"  f    - spawn an flags panel\n"
			+"  c    - close current frame\n"
			+"  .    - toggle maximize mode\n"
			+"  -    - horizontal split\n"
			+"  |    - vertical split\n"
			return "<h2>Help</h2>"
			+"<div id='"+name+"_help' style='background-color:#304050;overflow:scroll;height:100%'><pre>"+hlpmsg+"</div>";
		}
		t.new_frame (n, newthing (n), function(obj) {
			var flags = _(n+'_help');
			if (flags) { 
				var top = flags.style.offsetTop;
				var pos = findPos (flags);
				flags.style.height = obj.offsetHeight - pos[1]+20;
				flags.style.width = obj.style.width - pos[0];
			}
		});
	}
	function newConsoleFrame() {
		var n = t.defname ("console");
		function newthing(name) {
			return "<div><input id=\""+name+"_input\"></input></div>"
			+"<div id='"+name+"_output' class='frame_body'>"
			+"</div>";
		}

		t.new_frame (n, newthing (n), function(obj) {
			var flags = _(n+'_console');
			if (flags) { 
				var top = flags.style.offsetTop;
				var pos = findPos (flags);
				flags.style.height = obj.offsetHeight - pos[1]+20;
				flags.style.width = obj.style.width - pos[0];
			}
		}, null, function () {
				var input = _(n+"_input");
				input.onkeyup = function (ev) {
				if (ev.keyCode == 13) {
					r2.cmd (input.value, function(x) {
							_(n+"_output").innerHTML = "<pre>"+x+"</pre>";
							input.value = "";
						});
					}
				}
		});
	}
	function newFlagsFrame () {
		var n = t.defname ("flags");
		function newthing(name) {
			// TODO: disas_code id
			setTimeout (function () {
				r2.cmd ("fs *;f", function (x) {
					document.getElementById(name+"_flags").innerHTML="<pre>"+x+"</pre>";
				});
			}, 1);
			return "<h2>Flags</h2>"
			+"<div id='"+name+"_flags' class='frame_body'></div>";
		}
		t.new_frame (n, newthing (n), function(obj) {
			var flags = _(n+'_flags');
			if (flags) { 
				var top = flags.style.offsetTop;
				var pos = findPos (flags);
				flags.style.height = obj.offsetHeight - pos[1]+20;
				flags.style.width = obj.style.width - pos[0];
			}
		});
	}
	function newHexdumpFrame () {
		var n = t.defname ("hexdump");
		var msgbody = "<div id='"+n+"_code' class='frame_body'></div>";
		t.new_frame (n, msgbody, function(obj) {
			var code = _(n+'code');
			if (code) { 
				var top = code.style.offsetTop;
				var pos = findPos (code);
				code.style.height = obj.offsetHeight - pos[1]+20;
				code.style.width = obj.style.width - pos[0];
			}
		},null, function() {
			r2.cmd ("px 1024", function (x) {
				_(n+"_code").innerHTML="<pre>"+x+"</pre>";
			});
		});
	}
	function newDisasmFrame() {
		var n = t.defname ('disas');
		var disasmbody = "<div id='"+n+"_code' class='frame_body'></div>";
		t.new_frame (n, disasmbody, function(obj) {
			var code = _(n+'_code');
			if (code) { 
				var top = code.style.offsetTop;
				var pos = findPos (code);
				code.style.height = obj.offsetHeight - pos[1]+20;
				code.style.width = obj.style.width - pos[0];
			}
		}, null, function () {
			r2.cmd ("pd 512", function (x) {
				_(n+"_code").innerHTML="<pre>"+x+"</pre>";
			});
		});
	}
	function addPanel (pos) {
		ctr++;
		t.new_frame ('window_'+ctr, "<div id='div_"+ctr+"'><a href='#' id='cmd_"+ctr+"'>cmd</a><input></input></div>", pos);
		t.run ();
		t.update = function() {
			r2.cmd (t.cmd, function(x) {
				_(t.key).innerHTML = 
			"<div class='frame_body'><pre>"+x+"</pre></div>";
			});
		}
		_('cmd_'+ctr).onclick = function() {
			t.key = 'div_'+ctr;
			t.cmd = prompt ();
			t.update ();
		}
	}
	_('maximize').onclick = function() { t.maximize = !!!t.maximize; t.run(); }
	_('open-hex').onclick = function() { newHexdumpFrame(); }
	_('open-dis').onclick = function() { newDisasmFrame(); }
	_('open-fla').onclick = function() { newFlagsFrame(); }
	_('open-hlp').onclick = function() { newHelpFrame(); }
	_('open-con').onclick = function() { newConsoleFrame(); }
	_('add-column').onclick = function() {
		addPanel ("right");
	}
	_('add-row').onclick = function() {
		ctr++;
		t.new_frame ('window_'+ctr, "<div id='div_"+ctr+"'><a href='#' id='cmd_"+ctr+"'>cmd</a></div>", "bottom");
//		t.frames[0].push (t.frames.pop ()[0]);
		t.run();
		t.update = function() {
			r2.cmd (t.cmd, function(x) {
				_(t.key).innerHTML = 
				"<div class='frame_body'><pre>"+x+"</pre></div>";
			});
		}
		_('cmd_'+ctr).onclick = function() {
			t.key = 'div_'+ctr;
			t.cmd = prompt ();
			t.update ();
		}
	}
	newHexdumpFrame ();
	newDisasmFrame ();
	t.run ();
	window.onresize = function() {
		t.run ();
	}
	document.t = t;

	_('body').onkeyup = function (e) {
		var key = String.fromCharCode(e.keyCode);
		//if (!key.altKey) return;
		if (!e.altKey)
			return;
		key = e.keyCode;
		switch (key) {
		case 67:/*c*/ if (t.curframe) {t.oldframe = t.curframe; }
			t.del_frame(); t.run();break;
		case 189: // chrome
		case 173:/*-*/ addPanel ("bottom"); break;
		case 220: // chrome
		case 49:/*|*/ addPanel ("right"); break;
		case 190:/*.*/ t.maximize = !!!t.maximize; t.run(); break;
		case 72:/*h*/ t.other_frame('left'); break;
		case 74:/*j*/ t.other_frame('down'); break;
		case 75:/*k*/ t.other_frame('up'); break;
		case 76:/*l*/ t.other_frame('right'); break;
		case 88:
		case 'x': newHexdumpFrame (); break;
		case 68:
		case 'd': newDisasmFrame (); break;
/*
		case 'h': t.move_frame ('left'); break;
		case 'j': t.move_frame ('down'); break;
		case 'k': t.move_frame ('up'); break;
		case 'l': t.move_frame ('right'); break;
*/
		case 'i':
			r2.cmd ("pi 2", function(x){alert(x);});
			break;
		case '!':
			r2.cmd (prompt("Command to execute"), function(x){alert(x);});
			break;

		}
		//r2.cmd ("pi 2", alert);
	}
}
