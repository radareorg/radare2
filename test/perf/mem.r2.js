const logfile = 'a.txt';
const lines = r2.cmd('cat '+logfile).split(/\n/);
let total = 0;
let leaked = 0;
var track = {};
for (let line of lines) {
  const args = line.split(/ /g);
  if (line.startsWith ('mem::malloc')) {
    total += (0|+args[1]);
    leaked += (0|+args[1]);
    track[args[2]] = (0|+args[1]);
  } else if (line.startsWith ('mem::realloc')) {
    const a = args[1];
    const b = args[4];
    if ((0|+a) == 0) {
      track[b] = args[2];
    } else if (a == b) {
      track[b] = (0|+args[2]);
    } else {
      leaked -= track[a];
      delete track[a];
      track[b] = (0|+args[2]);
      leaked += track[b];
      // console.log(a,b);
    }
  } else if (line.startsWith ('mem::free')) {
    const args = line.split(/ /g);
    const a = args[1];
    if (!a) continue;
    if (track[a]) {
      // console.log("free",a);
      leaked -= (0|+track[a]);
      delete track[a];
    } else {
      // console.error('double free');
    }
  }
}
console.log('total', total);
console.log('leaked', leaked);

