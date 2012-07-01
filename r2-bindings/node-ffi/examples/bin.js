var r2 = require('../r_bin')

var b = new r2.RBin(), fileName = process.argv[2] || '/bin/ls';
if(!b.load(fileName, false))
	console.error('Cannot open '+fileName), process.exit(1);

console.log('Base address:', b.get_baddr().toString(16));
console.log('Sections:');
b.get_sections().forEach(function(x) {
	console.log('  %s: size=%d vsize=%d rva=%d offset=%s srwx=%s',
		x.name, x.size, x.vsize, x.rva,
		x.offset.toString(16), x.srwx.toString(16));
	});
console.log('Symbols:');
b.get_symbols().forEach (function(x) {
	console.log ('  %s: fw=%s bind=%s type=%s rva=%d offset=%s size=%d ordinal=%d',
		x.name, x.forwarder, x.bind, x.type, x.rva,
		x.offset.toString(16), x.size, x.ordinal);
	});
console.log('Imports:');
b.get_imports().forEach(function(x) {
	console.log('  %s: bind=%s type=%s rva=%d offset=%s ordinal=%d hint=%d',
		x.name, x.bind, x.type, x.rva,
		x.offset.toString(16), x.ordinal, x.hint);
	});
console.log('Strings:');
b.get_strings().forEach(function(x) {
	console.log('  %s rva=%d offset=%s ordinal=%d size=%d',
		JSON.stringify(x.string), x.rva,
		x.offset.toString(16), x.ordinal, x.size);
	});
