'use strict';
importScripts('/m/r2.js');

var howManyBytes;
var nbCols;
var configurationDone = false;

function hexPairToASCII(pair) {
	var chr = parseInt(pair, 16);
	if (chr >= 33 && chr <= 126) {
		return String.fromCharCode(chr);
	}

	return '.';
};

function getChunk(howManyBytes, addr, nbCols) {
	if (addr < 0) {
		return {
			offset: 0,
			hex: [],
			ascii: [],
			flags: [],
			modified: []
		};
	}

	var raw;

	// BUG? callback called more than once
	r2.cmd('p8 ' + howManyBytes + ' @' + addr, function(d) {
		raw = {
			offset: addr,
			hex: [],
			ascii: [],
			flags: [],
			modified: []
		};

		var hex = [];
		var ascii = '';
		for (var myIt = 0 ; myIt < howManyBytes ; myIt++) {
			var pair = d[myIt * 2] + d[(myIt * 2) + 1];
			hex.push(pair);
			ascii += hexPairToASCII(pair);
			if (myIt % nbCols === nbCols-1) {
				raw.hex.push(hex);
				raw.ascii.push(ascii);

				hex = [];
				ascii = '';
			}
		}
	});

	r2.cmdj('fij ' + addr + ' ' + (addr + howManyBytes), function(d) {
		raw.flags = d;
		for (var i in raw.flags) {
			raw.flags[i].size = parseInt(raw.flags[i].size);
		}
	});

	return raw;
}

self.onmessage = function(e) {
	if (!configurationDone || e.data.reset) {
		// Providing block size (how many byte retrieved)
		howManyBytes = e.data.howManyBytes;
		nbCols = e.data.nbCols;
		configurationDone = true;
	} else {
		// Sending the data from r2 (arg is start offset)
		// TODO: handle "substract" if partial required (first)
		var chunk = getChunk(howManyBytes, e.data.offset, nbCols);
		chunk.dir = e.data.dir;

		self.postMessage(chunk);
	}
};
