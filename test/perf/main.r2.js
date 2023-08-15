/// r2 performance testsuite ///

console.log('Running the benchmark testsuite for radare2')

const logFiles = r2.cmd('ls -q')
  .trim().split(/\n/g)
  .filter((x) => !x.startsWith('.'))
  .sort();

for (const log of logFiles) {
  console.log("LF", log);
  const tests = JSON.parse(r2.cmd('cat ' + log));
  for (let test of tests) {
    console.log(test.time_elapsed, '\t', test.name);
  }
}
