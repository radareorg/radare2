# readjson [![License][LicenseIMGURL]][LicenseURL] [![NPM version][NPMIMGURL]][NPMURL] [![Dependency Status][DependencyStatusIMGURL]][DependencyStatusURL] [![Build Status][BuildStatusIMGURL]][BuildStatusURL] [![Coverage Status][CoverageIMGURL]][CoverageURL]

Read file and parse it as json.

## Install

```
npm i readjson --save
```
## How to use?

```js
const readjson = require('readjson');

const json = await readjson('./package.json');

// throws if file not found
readjson.sync('./package.json');

readjson.sync.try('./package.json');
```

## License

MIT

[NPMIMGURL]:                https://img.shields.io/npm/v/readjson.svg?style=flat
[BuildStatusIMGURL]:        https://img.shields.io/travis/coderaiser/node-readjson/master.svg?style=flat
[DependencyStatusIMGURL]:   https://img.shields.io/david/coderaiser/node-readjson.svg?style=flat
[LicenseIMGURL]:            https://img.shields.io/badge/license-MIT-317BF9.svg?style=flat
[CoverageIMGURL]:           https://coveralls.io/repos/coderaiser/node-readjson/badge.svg?branch=master&service=github
[NPMURL]:                   https://npmjs.org/package/readjson "npm"
[BuildStatusURL]:           https://travis-ci.org/coderaiser/node-readjson  "Build Status"
[DependencyStatusURL]:      https://david-dm.org/coderaiser/node-readjson "Dependency Status"
[LicenseURL]:               https://tldrlegal.com/license/mit-license "MIT License"
[CoverageURL]:              https://coveralls.io/github/coderaiser/node-readjson?branch=master
