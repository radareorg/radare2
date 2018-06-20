Loading strings from binaries
=============================

TODO: explain bin.minstr

Config vars
-----------
```
bin.strings  =  [true]  - load strings from file
bin.rawstr   =  [false] - load strings from unknown rbin
```

Program args
------------
```
rabin2 -z   # list strings
rabin2 -zz  # list strings from raw binary (unknown rbin type)
```

Examples
--------
```
r2 -e bin.rawstr=true
r2 -z   # do not load strings (same as bin.strings=false)
r2 -zz  # load strings even if unknown bin (same as bin.rawstr=true)
r2 -n   # do not load symbols or anything
r2 -e bin.strings=false # load symbols but not strings
if (bin.strings) {
  if RBin.format(isKnown) {
    loadStrings()
  } else {
    if (bin.rawstr)
      loadStrings()
  }
}
```

