
function newHexdumpFrame(name) {
	// TODO: disas_code id
	setTimeout (function () {
		r2.cmd ("px 1024", function (x) {
			document.getElementById(name+"_code").innerHTML="<pre>"+x+"</pre>";
		});
	}, 1);
	return "<h2>Hexdump</h2>"
		+"<div id='"+name+"_code' style='background-color:#304050;overflow:scroll;height:100%'></div>";
}

function newDisasmFrame(name) {
	// TODO: disas_code id
	setTimeout (function () {
		r2.cmd ("pd 512", function (x) {
			document.getElementById(name+"_code").innerHTML="<pre>"+x+"</pre>";
		});
	}, 1);
	return "<h2>Disassembler</h2>"
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
	_('add-column').onclick = function() {
		ctr++;
		t.new_frame ('disas'+ctr, "test", "right");
		t.run();
	}
	_('add-row').onclick = function() {
		ctr++;
		t.new_frame ('disas'+ctr, "test", "bottom");
//		t.frames[0].push (t.frames.pop ()[0]);
		t.run();
	}
	t.new_frame ('hexdump', newHexdumpFrame ('hexdump'), function(obj) {
		var code = _('hexdump_code');
		if (code) { 
			var top = code.style.offsetTop;
			var pos = findPos (code);
			code.style.height = obj.offsetHeight - pos[1]+20;
			code.style.width = obj.style.width - pos[0];
		}
	});
	t.new_frame ('disas', newDisasmFrame ('disas'), function(obj) {
		var code = _('disas_code');
		if (code) { 
			var top = code.style.offsetTop;
			var pos = findPos (code);
			code.style.height = obj.offsetHeight - pos[1]+20;
			code.style.width = obj.style.width - pos[0];
		}
	});
	t.run();
	window.onresize = function() {
		t.run();
	}

	_('body').onkeyup = function (e) {
		switch (e.keyCode) {
		case 'x':
			var n = t.defname ("hexdump");
			t.new_frame (n, newHexdumpFrame (n), function(obj) {
				var code = _(n+'code');
				if (code) { 
					var top = code.style.offsetTop;
					var pos = findPos (code);
					code.style.height = obj.offsetHeight - pos[1]+20;
					code.style.width = obj.style.width - pos[0];
				}
			});
			break;
		case 'd':
			var n = t.defname ('disas');
			t.new_frame (n, newDisasmFrame (n), function(obj) {
				var code = _(n+'_code');
				if (code) { 
					var top = code.style.offsetTop;
					var pos = findPos (code);
					code.style.height = obj.offsetHeight - pos[1]+20;
					code.style.width = obj.style.width - pos[0];
				}
			});
			break;
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
