#!/usr/bin/env python3
"""Run after building: python3 test/scripts/test-r2pm-binary.py."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


R2PM = os.environ.get("R2PM", shutil.which("r2pm"))


class BinaryInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="r2pm-binary-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "git" / "radare2-pm" / "db"
        self.db.mkdir(parents=True)
        (self.db.parent / "README.md").write_text("Test database\n")
        self.env = os.environ.copy()
        self.env.update({
            "R2PM_DBDIR": str(self.db),
            "R2PM_GITDIR": str(self.db.parent.parent),
            "XDG_DATA_HOME": str(self.root / "data"),
            "R2PM_OFFLINE": "0",
            "R2_LOG_LEVEL": "1",
            "R2V": "6.2.2",
            "R2PM_PLATFORM": "any",
        })
        self.pkgdir = self.root / "data" / "radare2" / "r2pm" / "pkg"
        bindir = self.root / "data" / "radare2" / "prefix" / "bin"
        bindir.mkdir(parents=True)
        git = bindir / ("git.bat" if os.name == "nt" else "git")
        git.write_text("@echo SOURCE_CHECKOUT >&2\n@exit /b 1\n" if os.name == "nt"
                       else "#!/bin/sh\necho SOURCE_CHECKOUT >&2\nexit 1\n")
        git.chmod(0o755)

    def package(self, name, binary="echo BINARY", extra="", source=True):
        data = 'R2PM_BEGIN\nR2PM_DESC "binary test"\n' + extra + "\n"
        if source:
            data += "R2PM_INSTALL() {\necho SOURCE\n}\n"
            data += "R2PM_INSTALL_WINDOWS() {\necho SOURCE\n}\n"
        if binary is not None:
            data += "R2PM_BINSTALL() {\n" + binary + "\n}\n"
            data += "R2PM_BINSTALL_WINDOWS() {\n" + binary + "\n}\n"
        (self.db / name).write_text(data + "R2PM_END\n")

    def run_pm(self, *args, success=True):
        result = subprocess.run([R2PM, *args], env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertNotIn("SOURCE_CHECKOUT", result.stderr)
        return result

    def test_binary_skips_sources_and_build_dependencies(self):
        self.package("binary", extra='R2PM_GIT "https://invalid.invalid/source"\n'
                     'R2PM_NEEDS r2pm-missing-build-tool\nR2PM_DEPS missing-dependency')
        result = self.run_pm("-qbi", "binary")
        self.assertEqual(result.stdout.strip(), "BINARY")
        self.assertTrue((self.pkgdir / "binary").exists())
        self.assertFalse((self.db.parent.parent / "binary").exists())

    def test_missing_hook_does_not_fall_back(self):
        self.package("source", binary=None, extra='R2PM_GIT "https://invalid.invalid/source"')
        result = self.run_pm("-qbi", "source", success=False)
        self.assertEqual(result.stdout, "")
        self.assertIn("re-run without -b", result.stderr)
        self.assertFalse((self.pkgdir / "source").exists())

    def test_failing_hook_is_not_registered(self):
        self.package("failure", binary="exit /b 7" if os.name == "nt" else "exit 7")
        result = self.run_pm("-qbi", "failure", success=False)
        self.assertIn("re-run without -b", result.stderr)
        self.assertFalse((self.pkgdir / "failure").exists())

    def test_missing_package(self):
        result = self.run_pm("-qbi", "missing", success=False)
        self.assertIn("re-run without -b", result.stderr)

    def test_multiple_targets_preserve_failure(self):
        self.package("source", binary=None)
        self.package("binary")
        result = self.run_pm("-qbi", "source", "binary", success=False)
        self.assertEqual(result.stdout.strip(), "BINARY")
        self.assertTrue((self.pkgdir / "binary").exists())

    def test_selected_version_and_target_environment(self):
        script = ("echo %R2V% %R2PM_OS% %R2PM_ARCH% %R2PM_BITS%" if os.name == "nt"
                  else 'echo "$R2V $R2PM_OS $R2PM_ARCH $R2PM_BITS"')
        self.package("environment", binary=script)
        expected = ["6.2.2"] + [self.run_pm("-H", name).stdout.strip()
                                 for name in ("R2PM_OS", "R2PM_ARCH", "R2PM_BITS")]
        self.assertEqual(self.run_pm("-qbi", "environment").stdout.split(), expected)
        self.env.pop("R2V")
        expected[0] = self.run_pm("-qv").stdout.strip()
        self.assertEqual(self.run_pm("-qbi", "environment").stdout.split(), expected)

    def test_conflicts_still_prevent_binary_install(self):
        self.pkgdir.mkdir(parents=True)
        (self.pkgdir / "conflict").write_text("Global: false\n")
        self.package("binary", extra="R2PM_CONFLICT conflict")
        result = self.run_pm("-qbi", "binary", success=False)
        self.assertIn("conflicts with conflict", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_binary_only_package_is_searchable(self):
        self.package("binary", source=False)
        result = json.loads(self.run_pm("-qjs", "binary").stdout)
        self.assertEqual(result, [{"name": "binary", "desc": "binary test",
                                  "platforms": ["windows", "unix"], "supported": True}])
        self.assertIn("of 1 in database", self.run_pm("-qI").stdout)

    def test_source_install_is_unchanged(self):
        self.env["R2PM_OFFLINE"] = "1"
        if os.name == "nt":
            (self.db.parent.parent / "source").mkdir()
        self.package("source")
        self.assertEqual(self.run_pm("-qi", "source").stdout.strip(), "SOURCE")

    def test_global_binary_environment(self):
        script = "echo %GLOBAL% %R2PM_GLOBAL%" if os.name == "nt" else 'echo "$GLOBAL $R2PM_GLOBAL"'
        self.package("global", binary=script)
        self.assertEqual(self.run_pm("-qbgi", "global").stdout.strip(), "1 1")
        self.assertIn("Global: true", (self.pkgdir / "global").read_text())

    def test_uninstall_without_source_checkout(self):
        self.package("binary", extra='R2PM_GIT "https://invalid.invalid/source"')
        with (self.db / "binary").open("a") as package:
            package.write("\nR2PM_UNINSTALL() {\necho UNINSTALL\necho DONE\n}\n"
                          "R2PM_UNINSTALL_WINDOWS() {\necho UNINSTALL\necho DONE\n}\n")
        self.run_pm("-qbi", "binary")
        result = self.run_pm("-qu", "binary")
        self.assertEqual(result.stdout.split(), ["UNINSTALL", "DONE"])
        self.assertEqual(result.stderr, "")
        self.assertFalse((self.pkgdir / "binary").exists())


if __name__ == "__main__":
    unittest.main()
