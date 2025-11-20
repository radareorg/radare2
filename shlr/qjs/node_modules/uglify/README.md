# Uglify:

Uglify is a simple tool to uglify javascript & css files

## Installing:

```shell
 $ npm install -g uglify
```

## Usage:
```shell
  $ uglify -h

  Usage: uglify [options]

  Options:

    -h, --help            output usage information
    -V, --version         output the version number
    -s, --source <items>  source files
    -o, --output [value]  output file
    -c, --css             whether uglify css files
    -r, --root [value]    static root directory name, used to replace css urls with absolute path

  Examples:

    $ uglify -s ~/application.js,~/home.js -o ~/home.min.js
    $ uglify -s ~/application.css,~/home.css -o ~/home.min.css -c
    $ uglify -s ~/application.css,~/home.css -o ~/home.min.css -r public -c
```

## License:
MIT