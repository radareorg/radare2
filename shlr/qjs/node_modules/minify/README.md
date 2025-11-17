# Minify [![License][LicenseIMGURL]][LicenseURL] [![Build Status][BuildStatusIMGURL]][BuildStatusURL] [![NPM version][NPMIMGURL]][NPMURL] [![Coverage Status][CoverageIMGURL]][CoverageURL]

[NPMIMGURL]: https://img.shields.io/npm/v/minify.svg?style=flat
[BuildStatusURL]: https://github.com/coderaiser/minify/actions
[BuildStatusIMGURL]: https://github.com/coderaiser/minify/workflows/CI/badge.svg
[LicenseIMGURL]: https://img.shields.io/badge/license-MIT-317BF9.svg?style=flat
[NPM_INFO_IMG]: https://nodei.co/npm/minify.png?stars
[NPMURL]: http://npmjs.org/package/minify
[LicenseURL]: https://tldrlegal.com/license/mit-license "MIT License"
[CoverageURL]: https://coveralls.io/github/coderaiser/minify?branch=master
[CoverageIMGURL]: https://coveralls.io/repos/coderaiser/minify/badge.svg?branch=master&service=github

[Minify](http://coderaiser.github.io/minify "Minify") - a minifier of `js`, `css`, `html` and `img` files.

To get things done **Minify** uses this amazing tools:

- ✅ [@putout/minify](https://github.com/putoutjs/minify);
- ✅ [html-minifier](https://github.com/kangax/html-minifier);
- ✅ [clean-css](https://github.com/jakubpawlowicz/clean-css);
- ✅ [css-base64-images](https://github.com/Filirom1/css-base64-images);

## Install

For Node users:

```sh
npm i minify -g
```

For Deno users:

```js
import {minify} from 'npm:minify';
```

## How to use?

### CLI

```sh
Usage: minify [options]
Options:
  -h, --help                  display this help and exit
  -v, --version               display version and exit
  --js                        minify javascript
  --css                       minify css
  --html                      minify html
  --auto                      auto detect format
```

The bash command below creates a code snippet saved as `hello.js`.

Simply copy + paste the code starting with cat, including the EOT on the last line, and press <enter>.

```sh
$ cat << EOT > hello.js
const hello = 'world';

for (let i = 0; i < hello.length; i++) {
    console.log(hello[i]);
}
EOT
```

Use the command `minify` followed by the path to and name of the js file intended to be minified. This will minify the code and output it to the screen.

```sh
$ minify hello.js
var a='world';for(let i=0;i<a.length;i++)console.log(a[i]);
```

You can capture the output with the following:

```sh
$ minify hello.js > hello.min.js
```

You can pass input using `cat`:

```sh
cat << EOT | bin/minify.js --js
> const hello = 'world';
>
> for (let i = 0; i < hello.length; i++) {
>     console.log(hello[i]);
> }
> EOT
var a='world';for(let i=0;i<a.length;i++)console.log(a[i]);
```

`Minify` can be used with `async-await` and [try-to-catch](https://github.com/coderaiser/try-to-catch):

```js
import {minify} from 'minify';
import tryToCatch from 'try-to-catch';

const options = {
    html: {
        removeAttributeQuotes: false,
        removeOptionalTags: false,
    },
};

const [error, data] = await tryToCatch(minify, './client.js', options);

if (error)
    return console.error(error.message);

console.log(data);
```

## Options

For cli use these options can be provided in a JSON file named `.minify.json` like so:

```json
{
    "js": {
        "mangle": true,
        "mangleClassNames": true,
        "removeUnusedVariables": true,
        "removeConsole": false,
        "removeUselessSpread": true
    },
    "img": {
        "maxSize": 4096
    },
    "html": {
        "removeComments": true,
        "removeCommentsFromCDATA": true,
        "removeCDATASectionsFromCDATA": true,
        "collapseWhitespace": true,
        "collapseBooleanAttributes": true,
        "removeAttributeQuotes": true,
        "removeRedundantAttributes": true,
        "useShortDoctype": true,
        "removeEmptyAttributes": true,
        "removeEmptyElements": false,
        "removeOptionalTags": true,
        "removeScriptTypeAttributes": true,
        "removeStyleLinkTypeAttributes": true,
        "minifyJS": true,
        "minifyCSS": true
    },
    "css": {
        "compatibility": "*"
    }
}
```

**Minify** walking up parent directories to locate and read it’s configuration file `.minify.json`.

### `js`

In section related to `js` you can choose `type` of minifier:

- `putout` (default);
- [`terser`](https://github.com/terser/terser);

When you want to pass [options](https://github.com/terser/terser#minify-options) to `terser`, use section with the same name, `.minify.json` will look this way:

```json
{
    "js": {
        "type": "terser",
        "terser": {
            "mangle": false
        }
    }
}
```

## License

MIT
