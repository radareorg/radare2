var r2 = require('./r_core')

var b = new r2.RBin()
b.load('/bin/ls', false);

var baddr = b.get_baddr();
console.log('base address: ', baddr);

var sections = b.get_sections();
sections.forEach = function(x) {
    var iter = sections.iterator();
    while(!iter.isNull()) {
        var dat = iter.get_data();
        var s = new r2.types.RBinSection(dat.deref());
        console.log(dat);
        console.log('-->', s);
        console.log('-_>');
        iter = iter.get_next(); //
        console.log('next ', iter);
    }
}

var count = 4;
sections.forEach(function(x) {
    console.log('section', x);
});

var iter = sections.iterator();
while(iter != null) {
    console.log('------>');
    var dat = iter.get_data();
    console.log('data', dat);
    iter = iter.get_next();
    if(count--<1) {
        console.log('...');
        break;
    }
}
