
function newHexdumpFrame_html(name) {
	// TODO: disas_code id
	setTimeout (function () {
		r2.cmd ("px 1024", function (x) {
			document.getElementById(name+"_code").innerHTML="<pre>"+x+"</pre>";
		});
	}, 1);
	return "" //"<h2>Hexdump</h2>"
		+"<div id='"+name+"_code' style='background-color:#304050;overflow:scroll;height:100%'></div>";
}

function newDisasmFrame_html(name) {
	// TODO: disas_code id
	setTimeout (function () {
		r2.cmd ("pd 512", function (x) {
			document.getElementById(name+"_code").innerHTML="<pre>"+x+"</pre>";
		});
	}, 1);
	return "" // "<h2>Disassembler</h2>"
		+"<div id='"+name+"_code' style='background-color:#304050;overflow:scroll;height:100%'></div>";
}

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
			+"<div id='"+name+"_flags' style='background-color:#304050;overflow:scroll;height:100%'></div>";
		}
		t.new_frame (n, newthing (n), function(obj) {
			var flags = _(n+'flags');
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
		t.new_frame (n, newHexdumpFrame_html (n), function(obj) {
			var code = _(n+'code');
			if (code) { 
				var top = code.style.offsetTop;
				var pos = findPos (code);
				code.style.height = obj.offsetHeight - pos[1]+20;
				code.style.width = obj.style.width - pos[0];
			}
		});
	}
	function newDisasmFrame() {
		var n = t.defname ('disas');
		t.new_frame (n, newDisasmFrame_html (n), function(obj) {
			var code = _(n+'_code');
			if (code) { 
				var top = code.style.offsetTop;
				var pos = findPos (code);
				code.style.height = obj.offsetHeight - pos[1]+20;
				code.style.width = obj.style.width - pos[0];
			}
		});
	}
	_('maximize').onclick = function() { t.maximize = !!!t.maximize; t.run(); }
	_('open-hex').onclick = function() { newHexdumpFrame(); }
	_('open-dis').onclick = function() { newDisasmFrame(); }
	_('open-fla').onclick = function() { newFlagsFrame(); }
	_('add-column').onclick = function() {
		ctr++;
		t.new_frame ('window_'+ctr, "<div id='div_"+ctr+"'><a href='#' id='cmd_"+ctr+"'>cmd</a></div>", "right");
		t.run ();
		t.update = function() {
			r2.cmd (t.cmd, function(x) {
				_(t.key).innerHTML = 
				"<div style='background-color:#304050;overflow:scroll;height:100%'><pre>"+x+"</pre></div>";
			});
		}
		_('cmd_'+ctr).onclick = function() {
			t.key = 'div_'+ctr;
			t.cmd = prompt ();
			t.update ();
		}
	}
	_('add-row').onclick = function() {
		ctr++;
		t.new_frame ('window_'+ctr, "<div id='div_"+ctr+"'><a href='#' id='cmd_"+ctr+"'>cmd</a></div>", "bottom");
//		t.frames[0].push (t.frames.pop ()[0]);
		t.run();
		t.update = function() {
			r2.cmd (t.cmd, function(x) {
				_(t.key).innerHTML = 
				"<div style='background-color:#304050;overflow:scroll;height:100%'><pre>"+x+"</pre></div>";
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

	_('body').onkeyup = function (e) {
		switch (e.keyCode) {
		case 'x': newHexdumpFrame (); break;
		case 'd': newDisasmFrame (); break;
		case 'h': t.move_frame ('left'); break;
		case 'j': t.move_frame ('down'); break;
		case 'k': t.move_frame ('up'); break;
		case 'l': t.move_frame ('right'); break;
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
