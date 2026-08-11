#!/usr/bin/env node
// Boot the www/ image headless in v86 (the same emulator the browser runs)
// and periodically dump the VGA text screen, so image/browser problems can
// be reproduced without a browser: make webtest
"use strict";
const fs = require("fs");
const path = require("path");

const WWW = path.join(__dirname, "www");
const V86DIR = process.env.WEBTEST_V86 || WWW; // alternate libv86.js/v86.wasm
const TIMEOUT = (parseInt(process.env.WEBTEST_TIMEOUT, 10) || 180) * 1000;
const TYPE = process.env.WEBTEST_TYPE || ""; // keys to type once booted

const { V86 } = require(path.join(V86DIR, "libv86.js"));
const cfg = fs.readFileSync(path.join(WWW, "config.js"), "utf8");
const size = parseInt(cfg.match(/size: (\d+)/)[1], 10);
const acpi = !/acpi: false/.test(cfg);

const emulator = new V86({
	wasm_path: path.join(V86DIR, "v86.wasm"),
	memory_size: 256 * 1024 * 1024,
	vga_memory_size: 8 * 1024 * 1024,
	bios: { url: path.join(WWW, "seabios.bin") },
	vga_bios: { url: path.join(WWW, "vgabios.bin") },
	hda: { url: path.join(WWW, "images", "netbsd.img"), async: true, size: size },
	cdrom: process.env.WEBTEST_CDROM ? { url: process.env.WEBTEST_CDROM } : undefined,
	acpi: acpi,
	autostart: true
});

const grid = [];
emulator.add_listener("screen-put-char", function (a) {
	const row = a[0], col = a[1], chr = a[2];
	if (!grid[row]) {
		grid[row] = [];
	}
	grid[row][col] = chr >= 32 && chr < 127 ? String.fromCharCode(chr) : " ";
});

let last = "";
function dump (label) {
	const txt = grid.map(function (r) {
		return (r || []).map(function (c) { return c || " "; }).join("").replace(/\s+$/, "");
	}).join("\n").replace(/\n+$/, "");
	if (txt !== last) {
		last = txt;
		console.log("=== screen at " + label + " ===");
		console.log(txt);
	} else {
		console.log("=== screen unchanged at " + label + " ===");
	}
}

let typed = false;
setInterval(function () {
	dump(Math.round(process.uptime()) + "s");
	if (!typed && TYPE && /#\s*$/.test(last.trimEnd())) {
		typed = true;
		/* the guest polls the keyboard; sending a whole line at once
		 * overruns its buffer and characters get dropped */
		(TYPE + "\n").split("").forEach(function (ch, i) {
			setTimeout(function () { emulator.keyboard_send_text(ch); }, 150 * (i + 1));
		});
	}
}, 15000);

setTimeout(function () {
	dump("timeout");
	process.exit(0);
}, TIMEOUT);
