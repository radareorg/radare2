# Radare2 License

Most of radare2 is licensed under the LGPLv3, but as its dependencies and plugins are distributed with different licenses.

Probably the only concern for distributing static builds of radare2 is the **GPL** license, and you can skip the related code with the `--without-gpl` configure flag.

See `doc/licenses/` and `doc/licenses.md`.

To get a fully detailed SBOM report from a runtime build use the `licenses.r2.js` script that will return a JSON object with `-Vj` containing all the license and copyright detailed information of all the elements shipped in the build. Here's a sample output:

If you want to confirm the licenses you are shipping you can run the `scripts/licenses.r2.js` script to find out all the plugins and their copying statements.

```console
$ r2 -qi scripts/licenses.r2.js --
```
