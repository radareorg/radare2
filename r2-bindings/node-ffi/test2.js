var r2 = require ('./r_core');

var core = new r2.RCore() , cons = r2.RCons //.singleton ();

var fileName = process.argv[2] || '/bin/true';
var file = core.file_open(fileName, 0, 0);

if(file._pointer.isNull())
    console.error('Cannot open '+fileName), process.exit(1);

//core.bin_load('test.js');
//core.seek(0, true); core.block_read(0);
//core.cmd0('S 0x00000000 0x00000000 0x00013b30 0x00013b30 ehdr rwx');

core.cmd0('o');
core.cmd0('e io.va');
cons.flush();

console.log('sections {');
core.cmd0('om');
core.cmd0('S');
cons.flush();
console.log('}');

core.block_read(0);
core.cmd0('pD 8');
core.cmd0('? 33+4');
core.cmd0('x@0');
cons.flush();
