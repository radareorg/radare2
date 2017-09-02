const get = require('simple-get');
const path = require('path');
const colors = require('colors');

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
    xx: 0,
    br: 0
  };
  if (log)
  for (let line of log.replace('\r', '').split('\n')) {
    if (line.indexOf('XX]') !== -1) {
      obj.xx++;
    }
    if (line.indexOf('BR]') !== -1) {
      obj.br++;
    }
    obj.txt += line + '\n';
  }
  return obj;
}

async function processJob(job) {
  console.log(colors.green(`[BUILD] ${job.id} ${job.message}`));
  console.log(colors.yellow(`[TSTMP] ${job.id} ${job.started_at}`));
  console.log(colors.yellow(`[COMIT] ${job.id} ${job.commit}`));
  const buildInfo = await travis('builds/' + job.id, false);
  for (let job of buildInfo.matrix) {
    const travisLog = await travis(`jobs/${job.id}`, false);
    const result = parseLogs(travisLog.log);
    console.log('  [JOB]', job.id, 'XX:', result.xx, 'BR:', result.br);
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

main().then(process.exit).catch(console.error);
