'use strict';
importScripts('/m/r2.js');

var LINES = 80;
var MAXLINES = Math.round(LINES * 1.20); // +20%
var TOOLONG = (LINES * 2) * 3;

function appendTo(list, elems) {
	if (elems === null) {
		return;
	}
	for (var i = 0 ; i < elems.length ; i++) {
		var offset = parseInt(elems[i].offset);

		// If the "flag" is empty, we don't care
		if (elems[i].size == '0' || elems[i].size >= TOOLONG) {
			continue;
		}

		// If there is already a shortest element, don't care
		if (typeof list[offset] !== 'undefined' && elems[i].size <= list[offset]) {
			continue;
		}

		list[offset] = parseInt(elems[i].size);
	}
}

self.onmessage = function() {
	var data = {};

	var allFlags;
	r2.cmdj('fj ', function(flags) {
		allFlags = flags;
	});

	var allFcts;
	r2.cmdj('aflj', function(fcts) {
		allFcts = fcts;
	});

	appendTo(data, allFlags);
	appendTo(data, allFcts);

	self.postMessage(data);
};
