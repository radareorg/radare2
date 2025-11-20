var os = require('os'),
    fs = require('fs'),
    path = require('path'),
    _ = require('underscore'),
    string = require('underscore.string'),
    grunt = require('../node_modules/grunt/lib/grunt'),
    Uglify;

Uglify = function(sourceFiles, outputFile, isCss, staticRoot) {
    this.sourceFiles = this._parseSourceFiles(sourceFiles);
    this.outputFile = this._parsePath(outputFile);
    this.isCss = (isCss === true);
    this.staticRoot = staticRoot;
};

Uglify.prototype._parseSourceFiles = function(sourceFiles) {
    var _this = this;

    sourceFiles = _.map(sourceFiles, function(file) {
        file = _this._parsePath(file);

        if (fs.existsSync(file)) {
            return fs.realpathSync(file);
        }
        return null;
    });

    return _.uniq(
        _.filter(
            sourceFiles, function(sourceFile) {
                return sourceFile !== null
            }
        )
    );
};

Uglify.prototype._parsePath = function(file) {
    file = string.ltrim(file, './');

    if (string.startsWith(file, '/')) {
        return file;
    }

    if (string.startsWith(file, '~/')) {
        return path.join(process.env.HOME, string.ltrim(file, '~/'));
    }

    return path.join(process.cwd(), file);
};

Uglify.prototype.run = function() {
    var sourceFiles = this.sourceFiles,
        outputFile = this.outputFile,
        isCss = this.isCss,
        staticRoot = this.staticRoot,
        tasks = {
            copy: {
                main: {
                    files: []
                }
            },
            concat: {
                task: {
                    files: {}
                }
            },
            uglify: {
                task: {
                    files: {}
                }
            },
            cssmin: {
                task: {
                    files: {}
                }
            },
            clean: {
                files: [],
                options: {
                    force: true
                }
            }
        },
        tmpFiles,
        tmpDirPath,
        gruntfile;

    if (sourceFiles.length <= 0 || outputFile === null) {
        return true;
    }

    if (isCss) {
        if (staticRoot === null) {
            tasks.cssmin.task.files[outputFile] = sourceFiles;
        } else {
            tasks.css_url_replace = {
                task: {
                    options: {
                        staticRoot: staticRoot
                    },
                    files: {}
                }
            };
            tasks.css_url_replace.task.files[outputFile] = sourceFiles;
            tasks.cssmin.task.files[outputFile] = [outputFile];
        }
    } else {
        tmpFiles = [];
        tmpDirPath = path.dirname(outputFile) + '/dest';
        tasks.copy.main.files.push({
            extend: true,
            src: [sourceFiles],
            dest: tmpDirPath + '/',
            filter: 'isFile'
        });

        _.each(sourceFiles, function(sourceFile) {
            var tmpFile = tmpDirPath + sourceFile;
            tasks.uglify.task.files[tmpFile] = [sourceFile];
            tmpFiles.push(tmpFile);
        });
        tasks.concat.task.files[outputFile] = tmpFiles;
        tasks.clean.files = [tmpDirPath];
    }

    fs.writeFileSync(os.tmpdir() + '/grunt.json', JSON.stringify(tasks));
    if (isCss) {
        gruntfile = 'Gruntfile.css.js';
    } else {
        gruntfile = 'Gruntfile.js.js';
    }
    grunt.tasks(['build'], {gruntfile: __dirname + '/../' + gruntfile});
};

module.exports = Uglify;