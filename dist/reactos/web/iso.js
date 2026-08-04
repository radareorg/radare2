/* Minimal ISO-9660 writer used to pass host files to the guest through v86's
 * virtual CD-ROM. Files live in the root directory and use portable ISO names. */
(function (global) {
	"use strict";

	var BLOCK_SIZE = 2048;
	var MAX_FILE_BYTES = 128 * 1024 * 1024;

	function putLe16(buf, off, value) {
		buf[off] = value & 0xff;
		buf[off + 1] = value >>> 8 & 0xff;
	}

	function putBe16(buf, off, value) {
		buf[off] = value >>> 8 & 0xff;
		buf[off + 1] = value & 0xff;
	}

	function putBoth16(buf, off, value) {
		putLe16(buf, off, value);
		putBe16(buf, off + 2, value);
	}

	function putLe32(buf, off, value) {
		buf[off] = value & 0xff;
		buf[off + 1] = value >>> 8 & 0xff;
		buf[off + 2] = value >>> 16 & 0xff;
		buf[off + 3] = value >>> 24 & 0xff;
	}

	function putBe32(buf, off, value) {
		buf[off] = value >>> 24 & 0xff;
		buf[off + 1] = value >>> 16 & 0xff;
		buf[off + 2] = value >>> 8 & 0xff;
		buf[off + 3] = value & 0xff;
	}

	function putBoth32(buf, off, value) {
		putLe32(buf, off, value);
		putBe32(buf, off + 4, value);
	}

	function putText(buf, off, len, text) {
		var i;
		for (i = 0; i < len; i++) {
			buf[off + i] = i < text.length ? text.charCodeAt(i) & 0x7f : 0x20;
		}
	}

	function isoDate(date) {
		return [
			date.getUTCFullYear() - 1900,
			date.getUTCMonth() + 1,
			date.getUTCDate(),
			date.getUTCHours(),
			date.getUTCMinutes(),
			date.getUTCSeconds(),
			0
		];
	}

	function dirRecordLength(nameLength) {
		return 33 + nameLength + (nameLength % 2 ? 0 : 1);
	}

	function putDirRecord(buf, off, extent, size, flags, name, date) {
		var nameLength = typeof name === "number" ? 1 : name.length;
		var length = dirRecordLength(nameLength);
		var stamp = isoDate(date);
		var i;
		buf[off] = length;
		buf[off + 1] = 0;
		putBoth32(buf, off + 2, extent);
		putBoth32(buf, off + 10, size);
		for (i = 0; i < stamp.length; i++) {
			buf[off + 18 + i] = stamp[i];
		}
		buf[off + 25] = flags;
		buf[off + 26] = 0;
		buf[off + 27] = 0;
		putBoth16(buf, off + 28, 1);
		buf[off + 32] = nameLength;
		if (typeof name === "number") {
			buf[off + 33] = name;
		} else {
			putText(buf, off + 33, nameLength, name);
		}
		return length;
	}

	function cleanPart(text) {
		return text.toUpperCase().replace(/[^A-Z0-9_]/g, "_").replace(/^_+|_+$/g, "");
	}

	function portableName(name, used) {
		var leaf = String(name || "FILE").replace(/^.*[\\/]/, "");
		var dot = leaf.lastIndexOf(".");
		var stem = cleanPart(dot > 0 ? leaf.slice(0, dot) : leaf) || "FILE";
		var ext = cleanPart(dot > 0 ? leaf.slice(dot + 1) : "").slice(0, 8);
		var suffix = "";
		var number = 1;
		var candidate;
		for (;;) {
			var stemLength = 27 - suffix.length - (ext ? ext.length + 1 : 0);
			candidate = stem.slice(0, Math.max(1, stemLength)) + suffix + (ext ? "." + ext : "");
			if (!used[candidate]) {
				used[candidate] = true;
				return candidate;
			}
			number++;
			suffix = "_" + number;
		}
	}

	function alignBlock(value) {
		return Math.ceil(value / BLOCK_SIZE) * BLOCK_SIZE;
	}

	function layoutDirectory(entries) {
		var pos = dirRecordLength(1) * 2;
		var i;
		for (i = 0; i < entries.length; i++) {
			var length = dirRecordLength(entries[i].id.length);
			if (pos % BLOCK_SIZE + length > BLOCK_SIZE) {
				pos = alignBlock(pos);
			}
			entries[i].recordOffset = pos;
			pos += length;
		}
		return Math.max(BLOCK_SIZE, alignBlock(pos));
	}

	function putVolumeDescriptors(iso, sectors, rootSector, rootSize, now) {
		var pvd = 16 * BLOCK_SIZE;
		var end = 17 * BLOCK_SIZE;
		iso[pvd] = 1;
		putText(iso, pvd + 1, 5, "CD001");
		iso[pvd + 6] = 1;
		putText(iso, pvd + 8, 32, "RADARE2");
		putText(iso, pvd + 40, 32, "R2UPLOAD");
		putBoth32(iso, pvd + 80, sectors);
		putBoth16(iso, pvd + 120, 1);
		putBoth16(iso, pvd + 124, 1);
		putBoth16(iso, pvd + 128, BLOCK_SIZE);
		putBoth32(iso, pvd + 132, 10);
		putLe32(iso, pvd + 140, 18);
		putBe32(iso, pvd + 148, 19);
		putDirRecord(iso, pvd + 156, rootSector, rootSize, 2, 0, now);
		putText(iso, pvd + 190, 128, "RADARE2 BROWSER FILE TRANSFER");
		iso[pvd + 881] = 1;

		iso[end] = 255;
		putText(iso, end + 1, 5, "CD001");
		iso[end + 6] = 1;
	}

	function putPathTables(iso, rootSector) {
		var le = 18 * BLOCK_SIZE;
		var be = 19 * BLOCK_SIZE;
		iso[le] = iso[be] = 1;
		iso[le + 1] = iso[be + 1] = 0;
		putLe32(iso, le + 2, rootSector);
		putBe32(iso, be + 2, rootSector);
		putLe16(iso, le + 6, 1);
		putBe16(iso, be + 6, 1);
		iso[le + 8] = iso[be + 8] = 0;
	}

	async function build(files, progress) {
		var input = Array.prototype.slice.call(files || []);
		if (!input.length) {
			throw new Error("No files selected");
		}
		var totalBytes = input.reduce(function (sum, file) { return sum + file.size; }, 0);
		if (totalBytes > MAX_FILE_BYTES) {
			throw new Error("The selected files exceed the 128 MB transfer limit");
		}

		var used = Object.create(null);
		var entries = input.map(function (file) {
			var isoName = portableName(file.name, used);
			return { file: file, id: isoName + ";1", isoName: isoName, extent: 0 };
		});
		var rootSector = 20;
		var rootSize = layoutDirectory(entries);
		var nextSector = rootSector + rootSize / BLOCK_SIZE;
		var i;
		for (i = 0; i < entries.length; i++) {
			entries[i].extent = nextSector;
			nextSector += Math.ceil(entries[i].file.size / BLOCK_SIZE);
		}
		var sectorCount = Math.max(nextSector, rootSector + 1);
		var iso = new Uint8Array(sectorCount * BLOCK_SIZE);
		var now = new Date();
		putVolumeDescriptors(iso, sectorCount, rootSector, rootSize, now);
		putPathTables(iso, rootSector);

		var root = rootSector * BLOCK_SIZE;
		putDirRecord(iso, root, rootSector, rootSize, 2, 0, now);
		putDirRecord(iso, root + dirRecordLength(1), rootSector, rootSize, 2, 1, now);
		for (i = 0; i < entries.length; i++) {
			var entry = entries[i];
			var modified = entry.file.lastModified ? new Date(entry.file.lastModified) : now;
			putDirRecord(iso, root + entry.recordOffset, entry.extent, entry.file.size, 0, entry.id, modified);
			if (progress) {
				progress(i, entries.length, entry.file.name);
			}
			var data = await entry.file.arrayBuffer();
			iso.set(new Uint8Array(data), entry.extent * BLOCK_SIZE);
		}
		return {
			buffer: iso.buffer,
			bytes: totalBytes,
			names: entries.map(function (entry) {
				return { source: entry.file.name, target: entry.isoName };
			})
		};
	}

	global.R2ISO = { build: build, maxFileBytes: MAX_FILE_BYTES };
})(typeof window !== "undefined" ? window : globalThis);
