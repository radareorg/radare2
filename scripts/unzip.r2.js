// $ zip -r test.ipa /bin/ls /bin/sleep /etc/services
// $ r2 -qi unzip.r2.js --

const fileName = "test.ipa";
const tempDir = "tmpdir";

function walkDirectories(path, callback) {
	const files = r2.callj(`ls -j ${path}`);
	for (let file of files) {
		if (file.name.startsWith(".")) {
			continue;
		}
		const fullPath = `${path}/${file.name}`;
		if (file.isdir) {
			walkDirectories(fullPath, callback);
		} else {
			file.path = fullPath;
			callback(file);
		}
	}
}

function main() {
	r2.call(`!rm -rf ${tempDir}`)
	r2.call(`!unzip ${fileName} -d ${tempDir}`);
	walkDirectories(tempDir, (file) => {
		console.log("==> " + file.path);
		r = r2pipe.open(file.path);
		console.log(r.cmd("o"))
		r.quit();
	});
	r2.call(`!rm -rf ${tempDir}`)
}

main();
