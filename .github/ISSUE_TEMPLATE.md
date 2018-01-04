# This template is meant for bug reports, if you have a feature request, please be as descriptive as possible and delete the template

Make sure you are testing using the latest git version of radare2 before submitting any issue.

*If you would like to report a bug, please fill the template bellow*

### Work environment

| Questions                                            | Answers
|------------------------------------------------------|--------------------
| OS/arch/bits (mandatory)                             | Debian arm 64, Ubuntu x86 32 
| File format of the file you reverse (mandatory)      | PE, ELF etc.
| Architecture/bits of the file (mandatory)            | PPC, x86/32, x86/64 etc.
| r2 -v full output, **not truncated** (mandatory)         | radare2 2.2.0 16809 @....
| r2 -V full output in a pastebin document (mandatory) | https://pastebin.com

### Expected behavior

### Actual behavior

### Steps to reproduce the behavior 
- Use asciinema if you can and use code markdown `CODE` to make your code lisible
- Or even better, create a Pull-Request for the https://github.com/radare/radare2-regressions containing the test case examples can be found in the t/ folder see for example https://github.com/radare/radare2-regressions/blob/master/t/cmd_search#L7

### Additional Logs, screenshots, compiled binaries, source-code,  configuration dump, ...

Drag and drop zip archives containing the compiled binaries here, don't use external services or link.
