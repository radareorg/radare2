
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
	var position = "right";
	var t = new Tiled ('canvas');
	var ctr = 0;
	function newHelpFrame() {
		var n = t.defname ("help");
		function newthing(name) {
			// TODO: disas_code id
			setTimeout (function () {
				document.getElementById("randomcolors").onclick = function() {
					r2.cmd ("ecr", function () {
						t.update_all ();
					});
				}
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
			+"\n"
			//+"Blocksize <input type=''></input><br />"
			+"<input type='button' id='randomcolors' value='randomcolors'></input>"
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
		}, position, function () {
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
	function newDebugFrame() {
		var name = "debug";
		var n = t.defname (name);
		var fillFrame = function () {
			// TODO: list breakpoints with `dbj`
			r2.cmdj ("drj", function (regs) {
				r2.cmd ("pxQ@rsp", function (pxQ) {
					r2.cmd ("dbt", function (dbt) {
						r2.cmd ("dm", function (maps) { // TODO: use dmj
							var _ = function (x) { return document.getElementById(x); }
							setTimeout(function() {
								function updateAll() { t.update_all (); }
								_('dbg-step').onclick = function() {
									r2.cmd ("ds;.dr*", updateAll ());
								}
								_('dbg-over').onclick = function() {
									r2.cmd ("dso;.dr*", updateAll ());
								}
								_('dbg-skip').onclick = function() {
									r2.cmd ("dss;.dr*", updateAll ());
								}
								_('dbg-cont').onclick = function() {
									r2.cmd ("dc;.dr*", updateAll ());
								}
								_('dbg-until').onclick = function() {
									var until = prompt ("Until");
									if (until) {
										r2.cmd ("dcu "+until+";.dr*", updateAll ());
									}
								}
							},1);
							var str = '';
							str += " <a id='dbg-step' href='#'>[step]</a>";
							str += " <a id='dbg-over' href='#'>[over]</a>";
							str += " <a id='dbg-skip' href='#'>[skip]</a>";
							str += " <a id='dbg-cont' href='#'>[cont]</a>";
							str += " <a id='dbg-until' href='#'>[until]</a>";
							str +="<hr />Registers</hr>";
							str += '<table>';
							for (var r in regs) {
								var v = "0x"+(+regs[r]).toString (16);

								str += "<tr><td>"+
								r+"</td><td>"+
								"<a href=#>"+v+"</a></td></tr>";
							}
							str += '</table>';
							str += "<hr />Backtrace:<pre>"+dbt+"</pre>";
							str += "<hr />Stack:<pre>"+pxQ+"</pre>";
							str += "<hr />Maps:<pre>"+maps+"</pre>";
							document.getElementById(name+"_frame").innerHTML=str;
						});
					});
				});
			});
		}
		function newthing() {
			return "<h2>Debug</h2>"
			+"<div id='"+name+"_frame' class='frame_body'></div>";
		}
		t.new_frame (n, newthing (n), function(obj) {
			var flags = _(n+'_frame');
			if (flags) { 
				var top = flags.style.offsetTop;
				var pos = findPos (flags);
				flags.style.height = obj.offsetHeight - pos[1]+20;
				flags.style.width = obj.style.width - pos[0];
			}
		}, position, function (){
			try {
				fillFrame ();
			} catch (e) {
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
		}, position);
	}
	function newHexdumpFrame () {
		var n = t.defname ("hexdump");
		var msgbody = "<div id='"+n+"_hexdump' class='frame_body'></div>";
		t.new_frame (n, msgbody, function(obj) {
			var code = _(n+'code');
			if (code) { 
				var top = code.style.offsetTop;
				var pos = findPos (code);
				code.style.height = obj.offsetHeight - pos[1]+20;
				code.style.width = obj.style.width - pos[0];
			}
		}, position, function(frame, nf) {
			//frame = frame.curframe[0];
frame = nf;
			function calc() {
				var off = frame.offset || 0;
				r2.cmd ("px 1024 @ "+off, function (x) {
					var id_prev = n + '_hexdump_hex_prev';
					var id_next = n + '_hexdump_hex_next';
					var id_goto = n + '_hexdump_hex_goto';
					_(n+"_hexdump").innerHTML=
						"<br /><center><a class=link href='#' id="+id_prev+">[PREV]</a>"
						+"<a class=link href='#' id="+id_goto+">[GOTO]</a>"
						+"<a class=link href='#' id="+id_next+">[NEXT]</a></center>"
						+"<pre>"+x+"</pre>"
					;
					//var q = document.getElementById(n+'_hexdump_hex_prev');
					var q = document.getElementById(id_prev);
					q.onclick = function() {
						frame.offset = frame.offset | 0;
						frame.offset -= 512;
						frame.refresh ();
					}
					var q = document.getElementById(id_next);
					q.onclick = function() {
						frame.offset = frame.offset | 0;
						frame.offset += 512;
						frame.refresh ();
					}
					var q = document.getElementById(id_goto);
					q.onclick = function() {
						var newoff = prompt ("Goto");
						if (newoff) {
							r2.cmd ("?v "+newoff, function(val) {
								frame.offset = +val | 0;
								frame.refresh ();
							});
						}
					}
				});
			}
			if (!frame.offset) {
				r2.cmd ("?v entry0", function(val) {
					frame.offset = +val;
					calc (frame);
				});
			} else {
				calc (frame);
			}
		});
	}
	function newNotesFrame() {
		var n = t.defname ('notes');
		var disasmbody = "<div id='"+n+"_notes' class='frame_body'><textarea style='width:100%;height:100%'></textarea></div>";
		t.new_frame (n, disasmbody, function(obj) {
			var code = _(n+'_notes');
			if (code) { 
				var top = code.style.offsetTop;
				var pos = findPos (code);
				code.style.height = obj.offsetHeight - pos[1]+20;
				code.style.width = obj.style.width - pos[0];
			}
		}, position, function () {
			/* nothing */
		});
	}
	function newSettingsFrame() {
		var n = t.defname ('settings');
		var settbody = "<div id='"+n+"_settings' class='frame_body'>"
			+"<input type=button value=RandomColors>"
			+"</div>";
		t.new_frame (n, settbody, function(obj) {
			var code = _(n+'_settings');
			if (code) { 
				var top = code.style.offsetTop;
				var pos = findPos (code);
				code.style.height = "100%"; //obj.offsetHeight - pos[1]+20;
				code.style.width = obj.style.width - pos[0];
			}
		}, position, function () {
			r2.cmd ("e??", function (x) {
				_(n+"_settings").innerHTML="<pre>"+x+"</pre>";
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
				code.style.height = "100%"; //obj.offsetHeight - pos[1]+20;
				code.style.width = obj.style.width - pos[0];
			}
		}, position, function (frame, nf) {
			frame = frame.curframe[0];
frame = nf;
			var off = frame.offset || "entry0";
			r2.cmd ("pd 200 @ "+off, function (x) {
				var id_prev = n + '_code_prev';
				var id_next = n + '_code_next';
				var id_goto = n + '_code_goto';
				_(n+"_code").innerHTML=
					"<br /><center><a class=link href='#' id="+id_prev+">[PREV]</a>"
					+"<a class=link href='#' id="+id_goto+">[GOTO]</a>"
					+"<a class=link href='#' id="+id_next+">[NEXT]</a></center>"
					+"<pre>"+x+"</pre>";
				var q = document.getElementById(id_prev);
				q.onclick = function() {
					frame.offset = frame.offset | 0;
					frame.offset -= 512;
					frame.refresh ();
				}
				var q = document.getElementById(id_next);
				q.onclick = function() {
					frame.offset = frame.offset | 0;
					frame.offset += 512;
					frame.refresh ();
				}
				var q = document.getElementById(id_goto);
				q.onclick = function() {
					var newoff = prompt ("Goto");
					if (newoff) {
						r2.cmd ("?v "+newoff, function(val) {
							if (val) {
								frame.offset = newoff;
								frame.refresh ();
							}
						});
					}
				}
			});
		});
	}
	function addPanel (pos) {
		ctr++;
		position = pos;
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
	_('settings').onclick = function() { newSettingsFrame (); }
	_('refresh').onclick = function() { t.update_all(); }
	_('maximize').onclick = function() { t.maximize = !!!t.maximize; t.run(); }
	_('open-hex').onclick = function() { newHexdumpFrame(); }
	_('open-dis').onclick = function() { newDisasmFrame(); }
	_('open-fla').onclick = function() { newFlagsFrame(); }
	_('open-dbg').onclick = function() { newDebugFrame(); }
	_('open-hlp').onclick = function() { newHelpFrame(); }
	_('open-con').onclick = function() { newConsoleFrame(); }
	_('open-not').onclick = function() { newNotesFrame(); }
	_('add-column').onclick = function() {
		addPanel ("right");
	}
	_('add-row').onclick = function() {
		ctr++;
		position = "bottom";
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
