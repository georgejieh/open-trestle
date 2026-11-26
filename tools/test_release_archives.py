import hashlib
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import release_archives


def _write(root: Path, relative: str, content: bytes = b"x") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


class ReleaseArchiveTest(unittest.TestCase):
    def _inputs(self, root: Path, exe: str) -> tuple[Path, Path]:
        repository, build = root / "repo", root / "build"
        for relative in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES/secret-scanner/a/LICENSE"):
            _write(repository, relative)
        for relative in (f"bin/trestle{exe}", f"bin/trestled{exe}", f"libexec/open-trestle/open-trestle-scan-helper{exe}"):
            _write(build, relative, relative.encode())
        return repository, build

    def test_linux_archive_layout_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, build = self._inputs(root, "")
            target = ("linux", "amd64")
            destination = root / release_archives.archive_name("0.1.0-alpha.1", target)
            self.assertEqual(destination.name, "open-trestle-0.1.0-alpha.1-linux-amd64.tar.gz")
            entries = release_archives.archive_entries(repository, build, "0.1.0-alpha.1", target)
            release_archives.write_tar_gz(destination, entries, 1700000000)
            with tarfile.open(destination) as archive:
                members = {member.name: member for member in archive.getmembers()}
            top = "open-trestle-0.1.0-alpha.1-linux-amd64"
            self.assertEqual(members[f"{top}/libexec/open-trestle/open-trestle-scan-helper"].mode, 0o555)
            self.assertEqual(members[f"{top}/bin/trestle"].mode, 0o555)
            self.assertEqual(members[f"{top}/LICENSE"].mode, 0o444)
            self.assertTrue(members[f"{top}/bin"].isdir())
            self.assertIn(f"{top}/licenses/secret-scanner/a/LICENSE", members)
            self.assertIn(f"{top}/README.txt", members)
            self.assertTrue(all(name.startswith(top) for name in members))

    def test_windows_archive_and_sums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, build = self._inputs(root, ".exe")
            target = ("windows", "amd64")
            output = root / "dist"
            output.mkdir()
            destination = output / release_archives.archive_name("0.1.0", target)
            release_archives.write_zip(destination, release_archives.archive_entries(repository, build, "0.1.0", target), 0)
            with zipfile.ZipFile(destination) as archive:
                names = set(archive.namelist())
            self.assertIn("open-trestle-0.1.0-windows-amd64/libexec/open-trestle/open-trestle-scan-helper.exe", names)
            release_archives.write_sums(output)
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            self.assertEqual((output / "SHA256SUMS").read_text(), f"{digest}  {destination.name}\n")

    def test_missing_input_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository, build = self._inputs(root, "")
            (build / "bin/trestled").unlink()
            with self.assertRaisesRegex(ValueError, "unavailable"):
                release_archives.archive_entries(repository, build, "0.1.0", ("linux", "amd64"))


if __name__ == "__main__":
    unittest.main()
