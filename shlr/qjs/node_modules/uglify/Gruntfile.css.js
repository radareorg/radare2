module.exports = function(grunt) {
    var pkg = grunt.file.readJSON(require('os').tmpdir() + '/grunt.json'),
        replaceCssUrl = (typeof pkg.css_url_replace !== 'undefined');

    if (replaceCssUrl) {
        grunt.initConfig({
            css_url_replace: pkg.css_url_replace,
            cssmin: pkg.cssmin
        });
        grunt.loadNpmTasks('grunt-css-url-replace');
        grunt.loadNpmTasks('grunt-contrib-cssmin');
        grunt.registerTask('build', ['copy', 'css_url_replace', 'cssmin']);
    } else {
        grunt.initConfig({
            cssmin: pkg.cssmin
        });
        grunt.loadNpmTasks('grunt-contrib-cssmin');
        grunt.registerTask('build', ['cssmin']);
    }
};