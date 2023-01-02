# QJS

This is a trimmed down copy of the QuickJS fork of frida, which
follows upstream and includes a couple of bug fixes.

There's no formal releases of quickjs, so distros can't package
it directly, therefor it's better to ship it.

To update the source, rimraf the `src` folder and run `make`.

## How to update r2papi

* Edit `package.json` and set the new version.
* Run `npm i`
* Remove the r2papi.c and qjs files: `rm -f js_r2papi.*`
* Run `make`. that will regenerate them.

For a full rebuild of r2/qjs component and its plugin run this:

* sys/rebuild.sh qjs
