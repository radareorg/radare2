const get = require('simple-get');
const path = require('path');
const colors = require('colors');
const fs = require('fs');

const travisUrl = 'https://api.travis-ci.org';
const travisPath = 'radare/radare2';

async function travis(api, root, cb) {
  return new Promise((resolve, reject) => {
    const url = root
    ? [travisUrl, 'repos', travisPath, api].join('/')
    : [travisUrl, api].join('/');
    get.concat(url, (err, res, data) => { 
      if (err) {
        return reject(err);
      }
      const msg = data.toString();
      try {
        resolve(JSON.parse(msg));
      } catch (err) {
        resolve(msg);
      }
    });
  });
}

function parseLogs(log) {
  const obj = {
    txt: '',
    fx: 0,
    xx: 0,
    br: 0,
    issues: []
  };
  if (log) {
    let issue = '';
    let issueFound = false;
    let last = '';
    for (let line of log.split('\n')) {
      if (line.length === 0) {
        continue;
      }
      if (line.indexOf('FX]') !== -1) {
        obj.fx++;
      }
      if (line.indexOf('XX]') !== -1) {
        obj.xx++;
        console.log('   ' + line + last);
      } else if (line.indexOf('BR]') !== -1) {
        obj.br++;
      }
      last = line;
    }
  }
  obj.issues = obj.issues.length;
  return obj;
}

async function processJob(job) {
  console.log(colors.green(`[BUILD] ${job.id} (${job.state}) ${job.message}`));
  console.log(colors.yellow(`[-----] ${job.id} ${job.started_at} ${job.commit}`));
  const buildInfo = await travis('builds/' + job.id, false);
  for (let job of buildInfo.matrix) {
    const logFile = 'log-' + job.id + '.txt';
    const logExists = fs.existsSync(logFile);
    const travisLog = logExists
      ? { log: fs.readFileSync(logFile).toString() }
      : await travis(`jobs/${job.id}`, false);
    const log = (travisLog && travisLog.log)? travisLog.log.replace(/\r/g, '\n'): '';
    const result = parseLogs(log);
    if (!logExists) {
      fs.writeFileSync(logFile, log);
    }
    console.log('  [JOB]', job.id, 'XX:', result.xx, 'BR:', result.br, 'FX:', result.fx);
/*
    for (let issue of result.issues) {
  //    console.log('  - ', issue);
    }
*/
  }
}

async function main() {
  try {
    const builds = await travis('builds', true);
    let lastBuild;
    for (let build of builds) {
      if (build.state === 'finished' && build.duration > 3000) {
        await processJob(build);
      }
    }
  } catch (err) {
    console.error('Oops' , err);
  }
}

if (process.argv.length > 2) {
  console.log(parseLogs(fs.readFileSync(process.argv[2]).toString()));
} else {
  main().then(process.exit).catch(console.error);
}
