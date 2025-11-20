/*
 * grunt-css-url-replace
 * https://github.com/nanjingboy/grunt-css-url-replace
 *
 * Copyright (c) 2013 nanjingboy
 * Licensed under the MIT license.
 */

'use strict';
var Replace = require('../lib/replace');

module.exports = function(grunt) {

  // Please see the Grunt documentation for more information regarding task
  // creation: http://gruntjs.com/creating-tasks

  grunt.registerMultiTask('css_url_replace', 'Grunt task to replace css urls with absolute path', function() {
    // Merge task-specific and/or target-specific options with these defaults.
    var options = this.options({
      staticRoot: 'public'
    });

    // Iterate over all specified file groups.
    this.files.forEach(function(f) {
      // Concat specified files.
      var src = f.src.filter(function(filepath) {
        // Warn on and remove invalid source files (if nonull was set).
        if (!grunt.file.exists(filepath)) {
          grunt.log.warn('Source file "' + filepath + '" not found.');
          return false;
        } else {
          return true;
        }
      }).map(function(filepath) {
        // Read file source and replace relative url with absolute ones.
        return new Replace(filepath, options.staticRoot).run();
      }).join('\n');

      // Write the destination file.
      grunt.file.write(f.dest, src);

      // Print a success message.
      grunt.log.writeln('File "' + f.dest + '" created.');
    });
  });

};
