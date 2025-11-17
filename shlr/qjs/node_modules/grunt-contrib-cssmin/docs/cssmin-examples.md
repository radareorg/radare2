# Usage Examples

## Combine two files into one output file

```js
cssmin: {
  combine: {
    files: {
      'path/to/output.css': ['path/to/input_one.css', 'path/to/input_two.css']
    }
  }
}
```

## Add a banner
```js
cssmin: {
  add_banner: {
    options: {
      banner: '/* My minified css file */'
    },
    files: {
      'path/to/output.css': ['path/to/**/*.css']
    }
  }
}
```

## Minify all contents of a release directory and add a `.min.css` extension
```js
cssmin: {
  minify: {
    expand: true,
    cwd: 'release/css/',
    src: ['*.css', '!*.min.css'],
    dest: 'release/css/',
    ext: '.min.css'
  }
}
```
