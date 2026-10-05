#!/usr/bin/env python3

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]


class IOSPackagingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="r2-ios-cydia-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for directory in ("sys", "tools", "dist/plugins-cfg", "binr/blob", "libr/util", "libr/flag"):
            (self.root / directory).mkdir(parents=True)
        for name in ("ios-cydia.sh", "ios-env.sh"):
            shutil.copyfile(REPO / "sys" / name, self.root / "sys" / name)
        script = self.root / "sys/ios-cydia.sh"
        script.write_text(script.read_text().replace("/tmp/r2ios", str(self.root / "r2ios")))
        for name in ("dist/plugins-cfg/plugins.ios.cfg", "libr/util/libr_util.a", "libr/flag/libr_flag.a"):
            (self.root / name).touch()
        (self.root / "binr/blob/radare2").write_text("fixture binary\n")
        self.write_tool("configure", 'exit "${CONFIGURE_STATUS:-0}"\n')
        self.write_tool("tools/gcc", "exit 0\n")
        for name in ("ldid", "ldid2"):
            self.write_tool("tools/" + name, '''test -f "$2" || exit 98
printf '%s\\n' "$2" > "$TEST_ROOT/signed-path"
exit "${SIGNER_STATUS:-0}"
''')
        self.write_tool("tools/xcrun", 'exit "${STRIP_STATUS:-0}"\n')
        self.write_tool("tools/make", '''case "$*" in
clean) exit "${CLEAN_STATUS:-0}" ;;
-j4) exit "${BUILD_STATUS:-0}" ;;
USE_LTO=1) exit "${BLOB_STATUS:-0}" ;;
"-C binr ios-sdk-sign") exit "${SIGN_STATUS:-0}" ;;
install*)
    mkdir -p "$TEST_ROOT/r2ios/var/jb/usr/bin"
    cp "$TEST_ROOT/binr/blob/radare2" "$TEST_ROOT/r2ios/var/jb/usr/bin/radare2"
    ;;
PACKAGE=radare2)
    touch "$TEST_ROOT/packaged"
    exit "${PACKAGE_STATUS:-0}"
    ;;
*) exit 99 ;;
esac
''')
        self.write_tool("tools/sudo", 'exec "$@"\n')
        self.env = dict(os.environ, PATH=str(self.root / "tools") + os.pathsep + os.environ["PATH"])
        self.env["ROOTLESS"] = "1"
        self.env["CPU"] = "arm64"
        self.env["PACKAGE"] = "radare2"
        self.env["TEST_ROOT"] = str(self.root)

    def write_tool(self, name, body):
        path = self.root / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def assert_failure(self, variable, status):
        self.env[variable] = str(status)
        result = self.run_script()
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)

    def run_script(self, *args):
        return subprocess.run(
            ["sh", "sys/ios-cydia.sh", *args], cwd=self.root, env=self.env,
            capture_output=True, text=True, timeout=10,
        )

    def test_configure_failure(self):
        self.assert_failure("CONFIGURE_STATUS", 17)

    def test_clean_failure(self):
        (self.root / "config-user.mk").touch()
        self.assert_failure("CLEAN_STATUS", 18)

    def test_build_failure(self):
        self.assert_failure("BUILD_STATUS", 19)

    def test_blob_failure(self):
        self.assert_failure("BLOB_STATUS", 20)

    def test_strip_failure(self):
        self.assert_failure("STRIP_STATUS", 21)

    def test_signing_preparation_failure(self):
        self.assert_failure("SIGN_STATUS", 22)

    def test_signer_failure(self):
        self.assert_failure("SIGNER_STATUS", 23)
        self.assertFalse((self.root / "packaged").exists())

    def test_package_failure(self):
        self.assert_failure("PACKAGE_STATUS", 24)

    def test_rootless_package(self):
        (self.root / "tools/ldid2").unlink()
        result = self.run_script("makedeb")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "packaged").exists())
        self.assertEqual(
            (self.root / "signed-path").read_text().strip(),
            "dist/cydia/radare2/root/var/jb/usr/bin/radare2",
        )


if __name__ == "__main__":
    unittest.main()
