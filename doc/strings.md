# Loading strings from binaries

## Config vars

```console
bin.strings  =  [true]  - load strings from file
bin.rawstr   =  [false] - load strings from unknown rbin
bin.charset  =  []      - charset for scanning strings (bin.charset=? lists plugins)
```

`bin.charset` selects a muta charset for the string scanner. An explicit value
takes precedence over `RABIN2_CHARSET`, followed by the bin plugin's
`RBinInfo.charset` default. An empty value enables these defaults. This selection
also applies to raw string scans; it does not depend on loading core settings
from the bin plugin. For example:

```console
r2 -e bin.charset=ebcdic37 mainframe.bin
RABIN2_CHARSET=pokered rabin2 -zzz game.gb
```

`cfg.charset` selects the charset used when printing raw memory. The current
conversion path for string scanning still assumes that decoded bytes correspond
to source bytes; charsets that expand text can produce incorrect offsets and
truncate results.

## Program args

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

