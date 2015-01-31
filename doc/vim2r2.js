/*
# author: pancake <pancake@nopcode.org>
# description: Duktape/NodeJS script to convert VIM colorschemes for radare2
# copyright: 2015 LGPLv3
#
# Using NodeJS
# ------------
#
#  $ node vim2r2.js < /usr/share/vim/vim74/colors/slate.vim > slate.r2
#  $ r2 -i slate.r2 /bin/ls
#
# Using Duktape
# -------------
#  $ r2 -qi vim2r2.js -k colors=/usr/share/vim/vim74/colors/slate.vim --
*/

var DEBUG = false; //true;
var THEME = "/usr/share/vim/vim74/colors/slate.vim";

function colorToR2(c) {
	if (!c) return "";
	if (c[0]=='#') {
		return "rgb:"+c[1]+c[3]+c[5];
	}
	if (+c >0) {
		return {
			1: 'red',
			2: 'green',
			3: 'yellow',
			4: 'blue',
			5: 'magenta',
			6: 'cyan',
			7: 'white',
			8: 'gray',
		}[+c] || "cyan";
	}
	return {
		"red": "rgb:f00",
		"brown": "rgb:630",
		"darkcyan": "rgb:066",
		"darkblue": "rgb:006",
		"blue": "rgb:00f",
		"darkgreen": "rgb:030",
		"darkgrey": "rgb:666",
		"yellow": "yellow",
		"yellowgreen": "rgb:af3",
		"khaki": "rgb:550",
		"seagreen": "rgb:093",
		"magenta": "rgb:909",
		"green": "green",
		"goldenrod": "rgb:fa0",
		"white": "white",
		"black": "black",
		"gray": "rgb:888",
		"grey90": "rgb:999",
		"grey50": "rgb:777",
		"grey30": "rgb:777",
		"lightblue": "rgb:0bf",
		"slategrey": "rgb:999",
		"gold": "rgb:ff0",
		'cornflowerblue': 'rgb:46f',
		'navajowhite': 'rgb:ddd',
		'royalblue': 'rgb:47f'
	}[c.toLowerCase()] || c;
}

function watToR2(c) {
	return {
		'Comment': ["comment"],
		'Question': ["prompt"],
		'StatusLine': ["prompt"],
		'ErrorMsg': ["trap"],
		'Repeat': ["trap"],
		'Number': ["num"],
		'Operator': ["trap"],
		'Normal': ["trap"],
		'Constant': ["trap"],
		'Ignore': ["nop"],
		'Function': ["jmp","ujmp", "cjmp"],
		'LineNr': ["offset"],
		'MoreMsg': ["flow"],
		'IncSearch': ["help"],
		'Directory': ["call"],
		'NonText': ["other"],
		'Title': ["flag"],
		'Statement': ["num"],
		'Type': ["reg"]
	}[c] || [];
}

function v2r_parse(str) {
	var keys = {};
	function isHiLine(line) {
		if (line.indexOf ("hi ")==0)
			return true;
		if (line.indexOf (":hi ")==0)
			return true;
		return false;
	}
	var trim = function(s) {
		return String.prototype.trim.apply (s);
	}
	str = (""+str).replace(/\t/g,' ');
	str.split ('\n').map(trim).forEach (function (line) {
		if (line.indexOf ("let s:")==0) {
			console.log("# ", line);
		} else
		if (isHiLine (line)) {
			var words = line.split(" ").map(trim);
			var wat = words[1];
			function processColor(col) {
				var color = col.split('=')[1];
				var v = colorToR2 (color);
				watToR2 (wat).forEach (function (k) {
					keys[k] = v;
				});
			}
			if (DEBUG)
				console.log (line);
			var valid = [ 'ctermfg', 'guifg' ];
			valid.forEach (function (v) {
				for (var i = 2; i<words.length; i++) {
					var col = words[i];
					if (col.indexOf (v)==0)
						processColor (col);
				}
			});
		}
	});
	return keys;
}

function v2r_result(keys) {
	var str = [];
	for (var k in keys) {
		//console.log ("ec", k, keys[k]);
		str.push ( "ec "+ k+" "+ keys[k]);
	}
	return str.join ("\n");;
}

if (typeof process !== 'undefined') {
	var keys = {};
	process.stdin.on('data', function(x) {
		keys = v2r_parse(x);
	});
	process.stdin.on('end', function() {
		console.log (v2r_result (keys));
	});
} else {
	if (r2cmd) {
		var colors = r2cmd ("k colors").trim() || THEME;
		var data = r2cmd ("cat "+colors)
		if (data) {
			console.log (v2r_result (v2r_parse (data)));
		} else {
			console.error ("Cannot load "+colors);
		}
	} else {
		if (r2) {
			r2.cmd ("k colors", function(x) {
				var colors = x.trim() || THEME;
				r2.cmd ("cat "+colors, function(data) {
					if (data) {
						console.log (v2r_result (v2r_parse (data)));
					} else {
						console.error ("Cannot load "+colors);
					}
				});
			});
		} else {
			/* asuming its being used as an api */
		}
	}
}
