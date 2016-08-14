'use strict';
importScripts('/m/r2.js');
importScripts('/m/tools.js');

function extractOffset(str) {
	// comment line
	if (str.indexOf(';') !== -1) {
		return null;
	}
	var withoutHMTL = str.replace(/<[^>]*>/g, '');
	var res = withoutHMTL.match(/(0x[a-fA-F0-9]+)/);
	if (res === null) {
		return null;
	}
	return res[1];
};

function getChunk(where, howManyLines) {
	var raw;

	// Line retrieved from the current offset
	r2.cmd('pD ' + howManyLines + '@e:scr.color=1,scr.html=1 @' + where, function(d) {
		raw = d;
	});

	var lines = raw.split('\n');
	for (var i = 0 ; i < lines.length ; i++) {
		var offset = extractOffset(lines[i]);
		if (offset !== null) {
			lines[i] = '<span id=\'' + parseInt(offset, 16) + '\'>' + lines[i] + '</span>';
		}
	}

	var withContext = lines.join('\n');

	return '<pre style="border-bottom:1px dashed white;" title="'+where+'" id="block' + where + '">' + clickableOffsets(withContext) + '</pre>';
}

self.onmessage = function(e) {
	if (e.data.offset < 0) {
		self.postMessage({
			offset: 0,
			data: 'before 0x00'
		});
	} else {
		var chunk = {
			offset: e.data.offset,
			size: e.data.size,
			data: getChunk(e.data.offset, e.data.size)
		};

		// Sending the data from r2
		self.postMessage(chunk);
	}
};
