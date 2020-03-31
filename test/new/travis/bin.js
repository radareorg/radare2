const travis = require('./');

function run(p) {
  p.then(process.exit).catch(console.error);
}

if (process.argv.length > 2) {
  const arg = process.argv[2];
  if (arg === '-h') {
    console.log('Usage: bin.js [-p|-m|-h] [file] [+limit]');
    console.log(' -p : list pullreqs');
    console.log(' -m : list master');
    console.log(' -h : help message');
  } else if (arg === '-p' || arg === '-m') {
    run(travis(arg));
  } else if (arg === '-h') {
    console.log('Usage: logstat [file|+limit]');
  } else {
    if (+arg) {
      run(travis(+arg));
    } else {
      console.log(parseLogs(fs.readFileSync(process.argv[2]).toString()));
    }
  }
} else {
  run(travis(-1));
}
