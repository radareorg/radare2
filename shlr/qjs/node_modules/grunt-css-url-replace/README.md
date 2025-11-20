# grunt-css-url-replace

> Grunt task to replace css urls with absolute path

## Getting Started
This plugin requires Grunt `~0.4.5`

If you haven't used [Grunt](http://gruntjs.com/) before, be sure to check out the [Getting Started](http://gruntjs.com/getting-started) guide, as it explains how to create a [Gruntfile](http://gruntjs.com/sample-gruntfile) as well as install and use Grunt plugins. Once you're familiar with that process, you may install this plugin with this command:

```shell
npm install grunt-css-url-replace --save-dev
```

Once the plugin has been installed, it may be enabled inside your Gruntfile with this line of JavaScript:

```js
grunt.loadNpmTasks('grunt-css-url-replace');
```

### Options

#### options.staticRoot
Type: `String`
Default value: `'public'`

The root static directory in your website

### Usage Examples

```js
grunt.initConfig({
  css_url_replace: {
    options: {
      staticRoot: 'public'
    },
    replace: {
      files: {
        'dest/build.css': ['css/application.css', 'css/users/default.css']
      }
    }
  }
});
```

In this example, imagine the following folder structure and css contents:

```
public
├── css
│   └─── application.css
|   └─── users
|        └─── default.css
├── images
|   └── baner.png
|   └── avatar.png
```

#### css/application.css
```css
  .baner{background-image:url("../images/baner.png");}
  .baner{background-image:url("../images/baner.png#test");}
  .http { background-image: url("http://somehost.com/image.png"); }
  .https_urls { background-image: url("https://somehost.com/image.png"); }
```

#### css/users/default.css
```css
  .avatar{background-image:url("../../images/avatar.png");}
  .avatar{background-image:url("../../images/avatar.png?name=test");}
  .data_urls { background-image: url('data:image/png:base64,0'); }
  .backslashes_urls { background-image: url('\images\e.png') }
```

#### the generated file dest/build.css is would be:
```css
  .baner{background-image:url("/images/baner.png");}
  .baner{background-image:url("/images/baner.png#test");}
  .http { background-image: url("http://somehost.com/image.png"); }
  .https_urls { background-image: url("https://somehost.com/image.png"); }
  .avatar{background-image:url("/images/avatar.png");}
  .avatar{background-image:url("/images/avatar.png?name=test");}
  .data_urls { background-image: url("data:image/png:base64,0"); }
  .backslashes_urls { background-image: url("/images/e.png") }
```

## Contributors
* [superbug](https://github.com/superbug)
* [Nehle](https://github.com/Nehle)

## License
* [MIT](https://github.com/nanjingboy/grunt-css-url-replace/blob/master/LICENSE-MIT)