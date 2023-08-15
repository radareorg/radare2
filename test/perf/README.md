# Performance Suite

Run `make` to see the help.

## First session

To easiest command you can use is `make world`. That will build and run the benchmark suite for the last N commits.

```
$ make world
```

## Managing r2 versions

Use the `make use` target to select the version you like:

```
$ make use r2=5.8.8
```

To verify the installation check the output of this command:

```
$ make r2
```

## Generating Html Report

To do this just run `make html`. Which internally runs `make main > index.html` and opens the browser.

## TODO

* [ ] Per-test timing reports
* [ ] Canvas to draw lines with that info
