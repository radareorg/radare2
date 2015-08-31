Instructions to update this code
================================

Download latest GNU binutils

* overwrite
* s/#%/%/g - no # for decimal numbers
* s/\t/ /g - no tabs plz
* find all '" ; "' and remove related code
* find `info->symbols` references and comment them out
* Find " ; 0x" and remove all those refs
* Use git diff in case of doubt
* Remove all references to abort()
