module.exports = function(grunt) {
    var pkg = grunt.file.readJSON(require('os').tmpdir() + '/grunt.json');

    grunt.initConfig({
        copy: pkg.copy,
        uglify: pkg.uglify,
        concat: pkg.concat,
        clean: pkg.clean
    });
    grunt.loadNpmTasks('grunt-contrib-copy');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.registerTask('build', ['copy', 'uglify', 'concat', 'clean']);
};