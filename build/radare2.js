#!/usr/bin/node
// author: pancake <pancake@nopcode.org>

var M = require ('./make.js');

M.make ({
  configure: {
    'pkgname': 'radare2',
    'version': '0.9.5'
  },
  CC: 'ccache gcc',
  soext: 'dylib',
  root: '..',
  cflags: '-fPIC -I../libr/include',
  ldflags: '-fPIC',
  all: {
    targets: ['libr']
  },
  clean: {
    targets: ['all']
  },
  hash: {
    name: 'r_hash',
    path: 'libr/hash',
    type: 'library',
    files: [ "adler32.c", "calc.c", "crc16.c", "crc32.c",
      "crca.c", "entropy.c", "hamdist.c", "hash.c", "md4.c",
      "md5c.c", "sha1.c", "sha2.c", "state.c", "xxhash.c" ]
  },
  util: {
    name: 'r_util',
    path: 'libr/util',
    type: 'library',
    link: ['-liconv'],
    files: [ "base64.c", "base85.c", "bitmap.c",
      "btree.c", "buf.c", "cache.c", "calc.c", "chmod.c",
      "constr.c", "file.c", "flist.c", "graph.c", "hex.c",
      "ht.c", "ht64.c", "iconv.c", "judy64na.c", "list.c",
      "lock.c", "log.c", "mem.c", "mixed.c", "name.c",
      "num.c", "p_date.c", "p_format.c", "p_seven.c",
      "pool.c", "print.c", "prof.c", "randomart.c",
      "range.c", "sandbox.c", "slist.c", "str.c", "strht.c",
      "strpool.c", "sys.c", "thread.c", "uleb128.c", "w32-sys.c" ]
  },
  sdb: {
    name: 'sdb',
    type: 'library',
    path: 'shlr/sdb/src',
    files: [ "buffer.c", "cdb.c", "cdb_make.c", "ht.c", "lock.c",
      "ls.c", "main.c", "ns.c", "query.c", "sdb.c", "sdba.c",
      "sdbn.c", "util.c", "json.c" ]
  },
  db: {
    name: 'r_db',
    path: 'libr/db',
    links: ['util', 'sdb'],
    targets: ['util', 'sdb'],
    type: 'library',
    files: [ "db.c", "pair.c", "table.c" ]
  },
  reg: {
    name: 'r_reg',
    path: 'libr/reg',
    links: ['util'],
    targets: ['util'],
    type: 'library',
    files: [ "arena.c", "reg.c", "value.c" ]
  },
  cons: {
    name: 'r_cons',
    path: 'libr/cons',
    links: ['util'],
    targets: ['util', 'hash'],
    type: 'library',
    files: [ "cons.c", "grep.c", "hud.c", "input.c",
      "line.c", "output.c", "pal.c", "pipe.c", "rgb.c" ]
  },
  libr: {
    targets: ['cons', 'reg', 'db'],
  },
  binr: {
    modules: {
      'rasm2': {
        path: 'binr/rasm2'
      },
    }
  }
}).run ();
