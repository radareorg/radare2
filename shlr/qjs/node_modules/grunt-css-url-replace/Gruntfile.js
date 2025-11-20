/*
 * grunt-css-url-replace
 * https://github.com/nanjingboy/grunt-css-url-replace
 *
 * Copyright (c) 2013 nanjingboy
 * Licensed under the MIT license.
 */

'use strict';

module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({

    // Before generating any new files, remove any previously-created files.
    clean: {
      tests: ['tmp'],
    },

    // Configuration to be run (and then tested).
    css_url_replace: {
      task: {
        options: {
          staticRoot: 'test/fixtures'
        },
        files: {
          'tmp/replaced_url.css': [
            'test/fixtures/common.css',
            'test/fixtures/with_hash_or_query_string.css',
            'test/fixtures/absolute.css',
            'test/fixtures/backslashes.css'
          ]
        },
      },
    },

    // Unit tests.
    nodeunit: {
      tests: ['test/*_test.js'],
    },

  });

  // Actually load this plugin's task(s).
  grunt.loadTasks('tasks');

  // These plugins provide necessary tasks.
  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-contrib-nodeunit');

  // Whenever the "test" task is run, first clean the "tmp" dir, then run this
  // plugin's task(s), then test the result.
  grunt.registerTask('test', ['clean', 'css_url_replace', 'nodeunit']);

  // By default, run all tests.
  grunt.registerTask('default', ['test']);
};
