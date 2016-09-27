#!/usr/bin/env node
'use strict';

const exec = require('child_process').exec;
const spawn = require('child_process').spawn;
const AsciiTable = require('ascii-table');
const config = require('./config');

const lastTag = config.previousRelease;
const curVersion = config.releaseVersion;
const showOnlyFinalReport = true;
const codeName = config.codeName;
const topTen = 0;
const topFive = 999;

const authorAlias = {
  'sirmy15': 'ret2libc',
  'ahmedsoliman0x666': 'oddcoder',
  'jroi.martin': 'nibble',
  'ayman.khamouma': 'ayman',
  'rlaemmert': 'defragger',
  'maijin21': 'maijin',
  'krytarowski': 'kamil',
  'rakholiyajenish.07': 'p4n74',
  'P4N74': 'p4n74',
  'damien': 'damo22',
  'alvaro.felipe91': 'alvarofe',
  'lol': 'gk',
  'github.jdrake': 'jduck',
  'andrey.torsunov': 'torsunov',
  'gautier.colajanni': 'gautier',
  'davide.balzarotti': 'davide',
  'eternalsushant': 'sushant',
  'Qwokka': 'qwokka',
  'naveenboggarapu': 'naveen',
  'anton.kochkov': 'xvilka',
  'a.kochkov': 'xvilka',
  'incredible.angst': 'kolen',
};

const columns = [ 'name', 'commits', 'fix', 'add', 'honor', 'leak', 'esil', 'endian', 'authors' ];

const paths = [
  '', // total
  'binr/radare2',
  'binr/rabin2',
  'binr/radiff2',
  'binr/rahash2',
  // 'binr/ragg2',
  'libr/debug',
  'libr/bin',
  'libr/core',
  'libr/crypto',
  'libr/cons',
  'libr/anal',
  'libr/asm',
  'libr/util',
  'libr/egg',
  'libr/io',
  /*
  'libr/hash',
  'libr/bp',
   'libr/flags',
   'libr/diff',
   'libr/search',
   'shlr/sdb',
  'shlr/tcc',
   */
  'shlr/bochs',
  'man',
];

function execute(command, cb){
  let output = '';
  function callback(error, stdout, stderr) {
    cb(stdout);
  }
  exec (command, { maxBuffer: 1024 * 1024 * 1024 }, callback);
};

function getDifflines(upto, path, cb) {
  if (typeof upto === 'function') {
    cb = upto;
    path = '';
    upto = '';
  } else if (typeof path === 'function') {
    cb = path;
    path = '';
  }
  execute('git diff '+upto+'..@ '+path, (log) => {
    const o = {
      add: 0,
      del: 0
    };
  for (let line of log.split(/\n/g)) {
    if (line.match(/^\+/)) {
      o.add ++;
    } else if (line.match(/^-/)) {
      o.del ++;
    }
  }
  o.diff = o.add - o.del;
  cb (o);
});
}

function getChangelog(upto, path, cb) {
  path = __dirname + '/../../' + path;
  if (typeof upto === 'function') {
    cb = upto;
    path = '';
    upto = '';
  } else if (typeof path === 'function') {
    cb = path;
    path = '';
  }
  execute('git log '+upto+'..@ '+path, (log) => {
    let o = {
      upto: upto,
      path: path,
      authors: {},
      commits: [],
      fixes: []
    };
  const lines = log.split('\n');
  let date = null;
  let commit = null;
  let message = '';
  let numberFix = null;
  for (let line of lines) {
    if (line.match('^Author')) {
      const realname = line.substring(8);
      const author = renderAuthor(realname);
      if (o.authors[author] === undefined) {
        o.authors[author] = 1;
      } else o.authors[author]++;
    } else if (line.match('^Date:')) {
      date = line.substring(8);
    } else if (line.match('^commit')) {
      if (commit !== null) {
        const doh = {
          hash: commit,
          date: date,
          msg: message.trim()
        };
        if (doh.msg.match(/fix/i)) {
          numberFix = doh.msg.match(/#(\d+)/);
          if (numberFix != null)
            o.fixes.push(numberFix[1]);
        }

        o.commits.push(doh);
        message = '';
        date = '';
      }

      commit = line.substring(7);
    } else if (line[0] == ' ') {
      message += line.trim() + '\n';
    }
  }
  cb (o);
});
}

function countWord(x,y) {
  let count = 0;
  for (let a of x) {
    if (a.msg.match(y)) {
      count++;
    }
  }
  return count;
}

function computeStats(o) {
  return {
    commits: o.commits.length,
    fix: countWord(o.commits, /fix/i),
    crash: countWord(o.commits, /crash/i),
    'new': countWord(o.commits, /new/i),
    add: countWord(o.commits, /add/i),
    anal: countWord(o.commits, /anal/i),
    leak: countWord(o.commits, /leak/i),
    esil: countWord(o.commits, /esil/i),
    debug: countWord(o.commits, /debug/i),
    type: countWord(o.commits, /type/i),
    oob: countWord(o.commits, /oob/i),
    honor: countWord(o.commits, /honor/i),
    update: countWord(o.commits, /update/i),
    clean: countWord(o.commits, /clean/i),
    'import': countWord(o.commits, /import/i),
    endian: countWord(o.commits, /endian/i),
    indent: countWord(o.commits, /indent/i),
    command: countWord(o.commits, /command/i),
    enhance: countWord(o.commits, /enhance/i),
  }
}

function computeRanking(o) {
  let r = [];
  for (let a in o.authors) {
    r.push(o.authors[a]+ '  '+a);
    // console.log(a);
  }
  r = r.sort(function(a, b) {
    a = +((a.split(' ')[0]));
    b = +((b.split(' ')[0]));
    return (a < b) ? 1 : -1;
  });
  if (topTen > 0) {
    r = r.slice(0, topTen);
  }
  return {
    count: Object.keys(o.authors).length,
    authors: r
  };
}

function computeRepairs(o) {
  let r = [];
  o.fixes.forEach(function(elem) {
    r.push("[#" + elem + "](https://github.com/radare/radare2/issues/" + elem + ")");
  });
  return {
    count: Object.keys(o.fixes).length,
    fixes: r
  };
}

String.prototype.repeat = function(times) {
  return (new Array(times + 1)).join(this);
};

function printMdList(mdList, listLevel, total) {
  const elems = Object.keys(mdList);
  elems.forEach(function(elem) {
    if (elem === 'priv' || elem == 'path') {
      return;
    }
    let pc = '';
    if (total !== undefined) {
      const a = mdList[elem].split(' ')[0].trim();
      pc = [(100 * a / total) | 0, '%'].join('');
    }
    if (typeof mdList[elem] === 'object') {
      console.log('\t'.repeat(listLevel) + '- ' + elem + ':');
      return printMdList(mdList[elem], listLevel + 1);
    } else {
      const elemName = isNaN(elem) ? (elem + ': ') : '';
      console.log (pc, '\t'.repeat(listLevel) + '- ' + elemName + mdList[elem]);
    }
  });
}

function findStatsFor(as, x) {
  for (let c of as) {
    if (c.path == x) {
      return c;
    }
  }
  return undefined;
}

function renderAuthor(str) {
  for (let k in authorAlias) {
    const v = authorAlias[k];
    if (str.indexOf (k) != -1) {
      return v;
      // return str.replace(k, v);
    }
  }
  const res = str.match(/<([^@]*)/g);
  if (res !== null) {
    return res[0].substring(1).replace('@', '').trim();
  }
  return str;
}

function getAuthor(str) {
  const space = str.indexOf(' ');
  if (space !== -1) {
    return str.substring(space).trim();
  }
  return str;
}

var first = true;

function printFinalReportTable(obj) {
  function getFinalReportFor(x) {
    const arr = [];
    arr.push(x);
    let o = findStatsFor(obj, x);
    for (let col of columns.slice(1)) {
      const ocol = o[col];
      if (typeof ocol === 'undefined') {
        if (first) {
          first = false;
        } else {
          let auth = '';
          let countDown = 4;
          let last = topFive;
          for (let a of o.ranking.authors) {
            auth += getAuthor(a) + ' ';
            if (!last--) {
              break;
            }
            if (--countDown < 1) {
              auth += '...';
              break;
            }
          }
          arr.push (auth);
        }
      } else {
        arr.push (o[col]);
      }
    }
    return arr;
  }
  const table = new AsciiTable('Release ' + curVersion)
  paths.forEach((path) => {
    table.addRow(getFinalReportFor(path));
  });
  table.setHeading(columns);

  console.log('```');
  console.log(table.toString())
  console.log('```');
}

function getLogMessages(x) {
  function validMessage(msg) {
    return msg.indexOf('CID') === -1;
  }
  let msg = '';
  for (let m of x) {
    if (validMessage(m.msg)) {
      msg += m.msg + '\n';
    }
  }
  return msg;
}

function main() {
  let count = 0;
  let doner = [];
  let ready = false;

  console.log('Release ' + curVersion);
  console.log('==============');
  console.log();
  console.log('Project: radare2');
  console.log('Codename: ' + codeName);
  console.log('Date: ' + new Date().toString());
  console.log('Website: http://radare.org');
  console.log('Tarball: https://github.com/radare/radare2/releases');
  console.log();

  for (let onePath of paths) {
    count ++;
    getChangelog(lastTag, onePath, function(o) {
      getDifflines(lastTag, onePath, function(d) {
        let r = computeStats (o);
        r.path = onePath;
        r.ranking = computeRanking (o);
        r.repairs = computeRepairs (o);
        r.diff = d;
        r.priv = {
          commits: o.commits
        };
        doner.push (r);
        count --;
        if (count == 0 && ready) {
          if (!showOnlyFinalReport) {
            for (let oneDoner of doner) {
              printMdList(oneDoner, 0);
              console.log('\n');
            }
          }
          for (let oneDoner of doner) {
            if (oneDoner.path == '') {
              console.log('radare2 '+curVersion+' comes with '+oneDoner.diff.diff+' new lines of new features,'+
                  ' bug fixes and enhancements. Here some of the most important highlights:');
              console.log();
              console.log('Numbers:');
              console.log('--------');
              let r = oneDoner.ranking;
              let f = oneDoner.repairs;
              delete oneDoner.ranking;
              delete oneDoner.repairs;
              printMdList(oneDoner, 0);
              oneDoner.ranking = r;
              oneDoner.repairs = f;
              printFinalReportTable(doner);
              console.log();
              console.log('Contributors:', o.commits.length, '/', oneDoner.ranking.authors.length, '= ~',
                o.commits.length / oneDoner.ranking.authors.length);
              console.log('-------------');
              console.log();
              printMdList(oneDoner.ranking.authors, 0, o.commits.length);
              console.log();
              console.log('Commits:');
              console.log('--------');
              const logMessages = getLogMessages(oneDoner.priv.commits);
              console.log(logMessages);
              console.log();
              console.log('Fixes:');
              console.log('------');
              console.log();
              printMdList(oneDoner.repairs.fixes, 0);
            }
          }
        }
      });
    });
  }
  ready = true;
}

main();
