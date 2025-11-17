# Try Catch [![License][LicenseIMGURL]][LicenseURL] [![NPM version][NPMIMGURL]][NPMURL] [![Build Status][BuildStatusIMGURL]][BuildStatusURL] [![Coverage Status][CoverageIMGURL]][CoverageURL]

[NPMIMGURL]: https://img.shields.io/npm/v/try-catch.svg?style=flat
[BuildStatusIMGURL]: https://img.shields.io/travis/coderaiser/try-catch/master.svg?style=flat
[LicenseIMGURL]: https://img.shields.io/badge/license-MIT-317BF9.svg?style=flat
[NPMURL]: https://npmjs.org/package/try-catch "npm"
[BuildStatusURL]: https://travis-ci.org/coderaiser/try-catch "Build Status"
[LicenseURL]: https://tldrlegal.com/license/mit-license "MIT License"
[CoverageURL]: https://coveralls.io/github/coderaiser/readify?branch=master
[CoverageIMGURL]: https://coveralls.io/repos/coderaiser/readify/badge.svg?branch=master&service=github

Functional `try-catch` wrapper

## Install

```
npm i try-catch
```

## Example

```js
const tryCatch = require('try-catch');
const {parse} = JSON;
const [error, result] = tryCatch(parse, 'hello');

if (error)
    console.error(error.message);

```

## Related

- [try-to-catch](https://github.com/coderaiser/try-to-catch "TryToCatch") - functional try-catch wrapper for promises.

## License

MIT
