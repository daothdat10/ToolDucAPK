import base64
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

from ducapk.native import discover_native_libraries, collect_native_results
from ducapk.runner import analyze, retry_failed_only, AnalysisCancelled


def b64(text):
    return base64.b64encode(text.encode()).decode()


def write_script_outputs(directory, complete=True):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "methods.tsv").write_text(
        f"1\t00100000\t{b64('score')}\t{b64('Game')}\t{b64('int score(void)')}\n"
        f"2\t00100008\t{b64('move')}\t{b64('Game')}\t{b64('void move(void)')}\n",
        encoding="utf-8")
    # Address-keyed cache must survive changes to discovery indices.
    (directory / "results.tsv").write_text(
        f"00100000\tok\t{b64('int score(void) { return 5; }')}\n"
        "00100008\terror\t\n" + "interrupted\tok\t%%%",
        encoding="utf-8")
    if complete:
        (directory / "analysis_ready").touch()
        (directory / "script_complete").touch()


class NativeTests(unittest.TestCase):
    def test_selects_one_abi_and_skips_known_sdk(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "game.apk"
            with zipfile.ZipFile(apk, "w") as z:
                for abi in ("armeabi-v7a", "arm64-v8a"):
                    for name in ("libgame.so", "libfmod.so", "libsentry.so"):
                        z.writestr(f"lib/{abi}/{name}", b"\x7fELFdata")
            libs = discover_native_libraries([apk], root, {"game"}, lambda _: None, threading.Event())
            self.assertEqual([lib["name"] for lib in libs], ["libgame.so"])
            self.assertEqual(libs[0]["architecture"], "arm64-v8a")
            self.assertEqual((root / libs[0]["binary"]).read_bytes(), b"\x7fELFdata")

    def test_rejects_fake_elf(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "game.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("lib/arm64-v8a/libgame.so", b"not ELF")
            with self.assertRaisesRegex(ValueError, "ELF"):
                discover_native_libraries([apk], root, {"game"}, lambda _: None, threading.Event())
            self.assertFalse((root / "native_libraries.json").exists())

    def test_sdk_selection_and_archive_filename_cannot_escape_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "game.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("lib/arm64-v8a/libsentry.so", b"\x7fELFsdk")
                z.writestr("lib/arm64-v8a/C:escape.so", b"\x7fELFgame")
            libs = discover_native_libraries([apk], root, {"sdk", "game"}, lambda _: None, threading.Event())
            self.assertEqual(len(libs), 2)
            for lib in libs:
                self.assertTrue((root / lib["binary"]).resolve().is_relative_to(root / "native"))
                self.assertEqual(Path(lib["binary"]).name, "library.so")
            self.assertEqual(next(lib for lib in libs if lib["name"] == "libsentry.so")["category"], "sdk")

    def test_exports_browsable_results_and_tracks_missing_bodies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "native_libraries.json").write_text(json.dumps([
                {"key": "game", "name": "libgame.so", "architecture": "arm64-v8a"}]))
            (root / "job.json").write_text('{"with_ghidra":true}')
            write_script_outputs(root / "native" / "game")
            report = collect_native_results(root, lambda _: None)
            self.assertEqual(report["functions_with_body"], 1)
            self.assertEqual(report["functions_without_body"], 1)
            self.assertTrue(report["partial"])
            with closing(sqlite3.connect(root / "methods.sqlite")) as db:
                body = db.execute("SELECT body FROM results WHERE export_index=1").fetchone()[0]
                self.assertIn("return 5", body)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM methods").fetchone()[0], 2)
            self.assertIn("return 5", next((root / "classes_c").rglob("*.c")).read_text())
            # Recollection is idempotent; metadata-only does not report missing bodies.
            (root / "job.json").write_text('{"with_ghidra":false}')
            report = collect_native_results(root, lambda _: None)
            self.assertEqual(report["functions_without_body"], 0)
            self.assertFalse(report["partial"])

    def test_xapk_routes_native_and_retry_preserves_saved_options(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "split.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("lib/arm64-v8a/libgame.so", b"\x7fELFdata")
            xapk = root / "game.xapk"
            with zipfile.ZipFile(xapk, "w") as z:
                z.write(apk, "config.arm64.apk")
            calls = []
            def headless(directory, args, *rest):
                calls.append(args)
                write_script_outputs(directory)
                return 0
            with patch("ducapk.runner._headless", side_effect=headless), patch("ducapk.runner._run_jadx") as jadx:
                job = analyze([xapk], root / "out", lambda _: None, threading.Event(),
                              decompile_native=True, decompile_java=False, extract_levels=False)
                state = json.loads((job / "job.json").read_text())
                self.assertEqual(state["backend"], "Ghidra Native")
                self.assertEqual(state["status"], "partial")
                # Function discovery and decompilation are separate Ghidra runs.
                self.assertEqual(len(calls), 2)
                self.assertIn("-import", calls[0])
                self.assertEqual(calls[0][-2:], ["false", ""])
                self.assertIn("-process", calls[1])
                self.assertEqual(calls[1][-1], "true")
                report = retry_failed_only(job, lambda _: None, threading.Event())
                self.assertEqual(report["functions_with_body"], 1)
                self.assertEqual(len(calls), 4)
                jadx.assert_not_called()

    def test_cancel_keeps_native_results_and_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "game.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("lib/arm64-v8a/libgame.so", b"\x7fELFdata")
            def headless(directory, *args):
                write_script_outputs(directory, complete=False)
                raise AnalysisCancelled("stopped")
            with patch("ducapk.runner._headless", side_effect=headless):
                with self.assertRaises(AnalysisCancelled):
                    analyze([apk], root / "out", lambda _: None, threading.Event(),
                            decompile_native=True, decompile_java=False, extract_levels=False)
            job = next((root / "out").iterdir())
            self.assertEqual(json.loads((job / "job.json").read_text())["status"], "cancelled")
            report = json.loads((job / "report.json").read_text())
            self.assertEqual(report["functions_with_body"], 1)
            self.assertTrue(report["partial"])


if __name__ == "__main__":
    unittest.main()


def _elf_with_eh_frame(functions):
    """A minimal little-endian ELF64 with PT_LOAD + PT_GNU_EH_FRAME and one FDE per
    (address, size), the layout clang/lld emit for Android libraries."""
    import struct
    header_size, phdr_size = 64, 56
    hdr_at = header_size + 2 * phdr_size
    count = len(functions)
    eh_hdr_len = 12 + 8 * count
    frame_at = hdr_at + eh_hdr_len
    cie = struct.pack("<II", 0, 0) + bytes([1]) + b"zR\0" + bytes([1, 0x78, 30, 1, 0x1B])
    cie = cie + b"\0" * (-(len(cie) - 4) % 4)
    cie = struct.pack("<I", len(cie) - 4) + cie[4:]
    frame, fde_offsets = bytearray(cie), []
    for address, size in functions:
        start = frame_at + len(frame)
        fde_offsets.append(start)
        body = struct.pack("<I", start + 4 - frame_at)
        body += struct.pack("<i", address - (start + 8)) + struct.pack("<i", size) + bytes([0])
        body += b"\0" * (-len(body) % 4)
        frame += struct.pack("<I", len(body)) + body
    eh_hdr = bytes([1, 0x1B, 0x03, 0x3B]) + struct.pack("<i", frame_at - (hdr_at + 4))
    eh_hdr += struct.pack("<I", count)
    for (address, _), fde in sorted(zip(functions, fde_offsets)):
        eh_hdr += struct.pack("<ii", address - hdr_at, fde - hdr_at)
    total = frame_at + len(frame) + 0x400
    elf = bytearray(b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9)
    elf += struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, header_size, 0, 0, header_size, phdr_size, 2, 64, 0, 0)
    elf += struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    elf += struct.pack("<IIQQQQQQ", 0x6474E550, 4, hdr_at, hdr_at, hdr_at, eh_hdr_len, eh_hdr_len, 4)
    elf += eh_hdr + frame
    return bytes(elf + b"\0" * (total - len(elf)))


class EhFrameTests(unittest.TestCase):
    def test_function_starts_and_sizes_from_eh_frame(self):
        from ducapk.native import eh_frame_functions
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "libgame.so"
            binary.write_bytes(_elf_with_eh_frame([(0x500, 0x40), (0x400, 0x20), (0x540, 0x8)]))
            self.assertEqual(eh_frame_functions(binary), [(0x400, 0x20), (0x500, 0x40), (0x540, 0x8)])
            binary.write_bytes(b"\x7fELFdata")
            self.assertEqual(eh_frame_functions(binary), [])

    def test_sdk_libraries_are_not_game_code(self):
        from ducapk.native import library_category
        for name in ("libfmod.so", "libsentry-android.so", "libFirebaseCppApp-13_17_0.so",
                     "libapplovin-native-crash-reporter.so", "libunity.so", "libmain.so"):
            self.assertEqual(library_category(name), "sdk", name)
        for name in ("libgame.so", "libcocos2dcpp.so", "libUE4.so"):
            self.assertEqual(library_category(name), "game", name)
