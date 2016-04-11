'use strict';

var exec = require('child_process').exec;
var spawn = require('child_process').spawn;
function execute(command, cb){
	let output = '';
	function callback(error, stdout, stderr) {
		cb(stdout);
	}
	exec (command, { maxBuffer: 1024*1024*1024 }, callback)
};

function getDifflines(upto, path, cb) {
	if (typeof upto === 'function') {
		cb = upto;
		path = '';
		upto = '';
	} else if (typeof path === 'function') {
		cb = path;
		path = '';
	}
	execute('git diff '+upto+'..@ '+path, (log) => {
		let o = {
			add: 0,
			del: 0
		};
		for (let line of log.split(/\n/g)) {
			if (line.match(/^\+/)) {
				o.add ++;
			} else if (line.match(/^-/)) {
				o.del ++;
			}
		}
		o.diff = o.add - o.del;
		cb (o);
	});
}

function getChangelog(upto, path, cb) {
	if (typeof upto === 'function') {
		cb = upto;
		path = '';
		upto = '';
	} else if (typeof path === 'function') {
		cb = path;
		path = '';
	}
	execute('git log '+upto+'..@ '+path, (log) => {
		let o = {
			upto: upto,
			path: path,
			authors: {},
			commits: []
		};
		const lines = log.split('\n');
		let date = null;
		let commit = null;
		let message = '';
		for (let line of lines) {
			if (line.match("^Author")) {
				const author = line.substring(8);
				if (o.authors[author] === undefined) {
					o.authors[author] = 1;
				} else o.authors[author]++;
			} else if (line.match("^Date:")) {
				date = line.substring(8);
			} else if (line.match("^commit")) {
				if (commit !== null) {
					var doh = {
						hash: commit,
						date: date,
						msg: message.trim()
					};
					o.commits.push(doh);
					message = '';
					date = '';
				}
				commit = line.substring(7);
			} else if (line[0] == ' ') {
				message += line + '\n';
			}
		}
		cb (o);
	});
}

function countWord(x,y) {
	let count = 0;
	for (let a of x) {
		if (a.msg.match(y)) {
			count++;
		}
	}
	return count;
}

function computeStats(o) {
	return {
		commits: o.commits.length,
		fix: countWord(o.commits, /fix/i),
		crash: countWord(o.commits, /crash/i),
		'new': countWord(o.commits, /new/i),
		add: countWord(o.commits, /add/i),
		anal: countWord(o.commits, /anal/i),
		leak: countWord(o.commits, /leak/i),
		esil: countWord(o.commits, /esil/i),
		enhance: countWord(o.commits, /enhance/i),
	}
}

function computeRanking(o) {
	let r = [];
	for (let a in o.authors) {
		r.push(o.authors[a]+ '  '+a);
	//	console.log(a);
	}
	r = r.sort(function(a, b) {
		a = +((a.split(' ')[0]));
		b = +((b.split(' ')[0]));
		return (a < b) ? 1 : -1;
	});
	return {
		count: Object.keys(o.authors).length,
		authors: r
	};
}

const last_tag = '0.10.1';

const paths = [
	'', // total
	'binr/r2pm/d',
	'libr/debug',
	'libr/bin',
	'libr/core',
	'libr/crypto',
	'libr/cons',
	'libr/anal',
	'libr/asm',
	'man',
];

var count = 0;
var doner = [];
var ready = false;

for (let paz of paths) {
	count ++;
	getChangelog(last_tag, paz, function(o) {
		getDifflines(last_tag, paz, function(d) {
			let r = computeStats (o);
			r.path = paz;
			r.rank = computeRanking (o);
			r.diff = d;
			doner.push (r);
			count --;
			if (count == 0) {
				console.log (JSON.stringify (doner));
			}
		});
	});
}
ready = true;
