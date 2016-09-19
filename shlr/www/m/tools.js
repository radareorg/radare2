function E(x) {
	return document.getElementById(x);
}

function encode(r) {
	return r.replace(/[\x26\x0A\<>'"]/g, function(r) { return '&#' + r.charCodeAt(0) + ';';});
}

function clickableOffsets(x) {
	x = x.replace(/0x([a-zA-Z0-9]*)/g,
	'<a href=\'javascript:seek("0x$1")\'>0x$1</a>');
	x = x.replace(/sym\.([\.a-zA-Z0-9_]*)/g,
	'<a href=\'javascript:seek("sym.$1")\'>sym.$1</a>');
	x = x.replace(/fcn\.([\.a-zA-Z0-9_]*)/g,
	'<a href=\'javascript:seek("fcn.$1")\'>fcn.$1</a>');
	x = x.replace(/str\.([\.a-zA-Z0-9_]*)/g,
	'<a href=\'javascript:seek("str.$1")\'>str.$1</a>');
	return x;
}
