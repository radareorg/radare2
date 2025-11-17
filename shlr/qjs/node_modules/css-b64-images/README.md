[![build status](https://secure.travis-ci.org/Filirom1/css-base64-images.png)](http://travis-ci.org/Filirom1/css-base64-images)
css-base64-images
=================

Base64 images in your css file.

![Base64](https://github.com/Filirom1/css-base64-images/raw/master/draft.png)

Transform this:

    .single-quote {
      background: url('../img/background-pattern.gif');
    }

into

    .single-quote {
      background: url('data:image/gif;base64,R0lGODlhBgAGAIAAAObm5vLy8iH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS4wLWMwNjAgNjEuMTM0Nzc3LCAyMDEwLzAyLzEyLTE3OjMyOjAwICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M1IE1hY2ludG9zaCIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpFMEY0NTFERjVEQ0ExMUUwOURGQ0Y2NjAyQTkzMUQ2OSIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDpFMEY0NTFFMDVEQ0ExMUUwOURGQ0Y2NjAyQTkzMUQ2OSI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOkUwRjQ1MURENURDQTExRTA5REZDRjY2MDJBOTMxRDY5IiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOkUwRjQ1MURFNURDQTExRTA5REZDRjY2MDJBOTMxRDY5Ii8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+Af/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2djX1tXU09LR0M/OzczLysnIx8bFxMPCwcC/vr28u7q5uLe2tbSzsrGwr66trKuqqainpqWko6KhoJ+enZybmpmYl5aVlJOSkZCPjo2Mi4qJiIeGhYSDgoGAf359fHt6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYWBfXl1cW1pZWFdWVVRTUlFQT05NTEtKSUhHRkVEQ0JBQD8+PTw7Ojk4NzY1NDMyMTAvLi0sKyopKCcmJSQjIiEgHx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQAAIfkEAAAAAAAsAAAAAAYABgAAAgqMDYcaqX6AnKAAADs=');
    }

Only works with CSS files.

Works with:

* single quotes: url('../img/background-pattern.gif');
* double quotes: url("../img/background-pattern.gif");
* absolute URL: url("/img/background-pattern.gif"); but you must specify a `root` path

Do not work with (a warning is shown, but the process continue)

* File bigger than 4Ko (configurable)
* external urls: url("http://my-company.ext/img/background-pattern.gif");
* not found images

## Install

    npm install -g css-b64-images

## Usage

    cd /your/www/root/dir
    css-b64-images css/styles.css > css/style.optimized.css

## As a library

### From File

fromFile(cssFile, root, [options,] cb)

You must specify the `root` path for absolute URLs to work.

    var b64img = require('css-b64-images');

    b64img.fromFile('/your/www/root/dir/css/your-stylesheet.css', '/your/www/root/dir/', function(err, css){
      if(err) console.error('Error:', err);
      console.log(css);
    });

### From String

fromString(css, relativePath, rootPath, [options,] cb)

    var b64img = require('css-b64-images');
    var css = fs.readFileSync('/your/www/root/dir/css/your-stylesheet.css');

    b64img.fromString(css, '/your/www/root/dir/css/', '/your/www/root/dir/', function(err, css){
      if(err) console.error('Error:', err);
      console.log(css);
    });

### Options

* maxSize: (default 4096) bigger images are not base64 in the CSS


## LICENSE

MIT
