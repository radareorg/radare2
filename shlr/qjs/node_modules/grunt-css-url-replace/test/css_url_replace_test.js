'use strict';

var grunt = require('grunt');


exports.css_url_replace = {
  setUp: function(done) {
    // setup here if necessary
    done();
  },

  task: function(test) {
    test.expect(1);

    var actual = grunt.file.read('test/expected/replaced_url.css');
    var expected = grunt.file.read('tmp/replaced_url.css');
    test.equal(actual, expected, 'Css url replaced failed.');

    test.done();
  },
};
