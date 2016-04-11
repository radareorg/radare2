'use strict';

var exec = require('child_process').exec;
function execute(command, callback){
	exec(command, function(error, stdout, stderr){ callback(stdout); });
};

module.exports.getGitUser = function(callback){
    execute("git config --global user.name", function(name){
        execute("git config --global user.email", function(email){
            callback({ name: name.replace("\n", ""), email: email.replace("\n", "") });
        });
    });
};

function getTags() {
	let tags = {};
	
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
				if (o.authors[author] === undefined) 
				o.authors[author] = 0;
				else o.authors[author]++;
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
	console.log('Commits', o.commits.length);
	console.log('Fix', countWord(o.commits, /fix/i))
	console.log('Crash', countWord(o.commits, /crash/i))
	console.log('New', countWord(o.commits, /new/i))
	console.log('Add', countWord(o.commits, /add/i))
	console.log('Anal', countWord(o.commits, /anal/i))
	console.log('ESIL', countWord(o.commits, /esil/i))
	console.log('enhance', countWord(o.commits, /enhance/i))
}

function computeRanking(o) {
	let r = [];
	for (let a in o.authors) {
		r.push(o.authors[a]+ '  '+a);
		console.log(a);
	}
	r = r.sort(function(a, b) {
		return +a - +b;
	});
	console.log(r);
}

getChangelog('0.10.1', '', function(o) {
	//console.log(JSON.stringify(o));
	computeRanking (o);
	computeStats (o);
});
