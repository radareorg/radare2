# How to report issues

Before reporting an issue with GitHub, be sure that:
* you are using the git version of radare2
* you are using a clean installation
* the issue was not already reported

When the above conditions are satisfied, feel free to submit an issue
while trying to be as precise as possible. If you can, provide the problematic
binary, the steps to reproduce the error and a backtrace in case of SEGFAULTs.
Any information will help to fix the problem.

# How to contribute

There are a few guidelines that we need contributors to follow so that we can
try to keep the codebase consistent and clean.

## Getting Started

* Make sure you have a GitHub account.
* Fork the repository on GitHub.
* Create a topic branch from master. Please avoid working directly on the ```master``` branch.
* Make commits of logical units.
* Check for coding style issues with ```git diff master..mybranch | ./sys/clang-format-diff.py -p1``` and be sure to follow the CODINGSTYLE (more on this in [DEVELOPERS.md](https://github.com/radareorg/radare2/blob/master/DEVELOPERS.md)).
* Submit the Pull Request(PR) on Github.
* When relevant, write a test in [test/](test).

# Additional resources

* [README.md](https://github.com/radareorg/radare2/blob/master/README.md)
* [DEVELOPERS.md](https://github.com/radareorg/radare2/blob/master/DEVELOPERS.md)
