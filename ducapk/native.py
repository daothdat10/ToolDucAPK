"""Native ELF discovery and exports, independent of Unity metadata."""
from __future__ import annotations

import base64
from contextlib import closing
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import zipfile

from .archive import ARCHITECTURES


# A conservative filename heuristic, recorded in the manifest for inspection.
SDK_LIBRARIES = {"libc++_shared.so", "libfmod.so", "libfmodstudio.so",
                 "libsentry.so", "libsentry-android.so", "libcrashlytics.so",
                 "libFirebaseCppApp.so", "libappsflyer.so"}


def discover_native_libraries(apks: list[Path], job: Path, categories: set[str],
                              emit, cancel) -> list[dict]:
    manifest = job / "native_libraries.json"
    if manifest.is_file():
        return json.loads(manifest.read_text(encoding="utf-8"))
    candidates = {}
    for apk in apks:
        with zipfile.ZipFile(apk) as archive:
            for info in archive.infolist():
                parts = info.filename.split("/")
                if (len(parts) != 3 or parts[0] != "lib" or
                        parts[1] not in ARCHITECTURES or not parts[2].endswith(".so")):
                    continue
                key = (parts[1], parts[2])
                candidate = (apk, info.filename, info.file_size)
                if key in candidates and candidates[key] != candidate:
                    raise ValueError(f"Thư viện native trùng tên {key}: chọn split APK của cùng một game.")
                candidates[key] = candidate
    if not candidates:
        raise ValueError("Không tìm thấy thư viện native lib/<ABI>/*.so trong APK.")
    architecture = next(abi for abi in ARCHITECTURES if any(k[0] == abi for k in candidates))
    result = []
    for (abi, name), (apk, member, size) in sorted(candidates.items()):
        if abi != architecture:
            continue
        category = "sdk" if name in SDK_LIBRARIES else "game"
        if category not in categories:
            continue
        if cancel.is_set():
            # Avoid a dependency on runner's cancellation exception.
            raise InterruptedError("Đã dừng trích thư viện native.")
        digest = hashlib.sha1(name.encode()).hexdigest()[:8]
        key = re.sub(r"[^A-Za-z0-9_-]", "_", name)[:60] + "_" + digest
        directory = job / "native" / key
        directory.mkdir(parents=True, exist_ok=True)
        # Never use an archive-controlled filename as a Windows output path.
        target = directory / "library.so"
        with zipfile.ZipFile(apk) as archive, archive.open(member) as source, target.open("wb") as output:
            if source.read(4) != b"\x7fELF":
                raise ValueError(f"Thư viện {name} không có header ELF hợp lệ.")
            output.write(b"\x7fELF")
            shutil.copyfileobj(source, output, 1024 * 1024)
        result.append({"key": key, "name": name, "architecture": abi, "category": category,
                       "size": size, "source": f"{apk}!{member}",
                       "binary": target.relative_to(job).as_posix()})
        emit(f"Đã lấy {abi} {name} ({size:,} byte); nhóm {category} theo tên thư viện.")
    if not result:
        raise ValueError("Không có thư viện native trong nhóm đã chọn. Chọn Logic game hoặc SDK.")
    manifest.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def _decoded(value: str) -> str:
    return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")


def collect_native_results(job: Path, emit) -> dict:
    """Rebuild browser/export data from durable per-library manifests and results."""
    libraries = json.loads((job / "native_libraries.json").read_text(encoding="utf-8"))
    info = json.loads((job / "job.json").read_text(encoding="utf-8"))
    pseudocode = bool(info.get("with_ghidra", True))
    total = success = 0
    failures, counts = [], {}
    with closing(sqlite3.connect(job / "methods.sqlite")) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS methods (id INTEGER PRIMARY KEY, export_index INTEGER, "
                   "address INTEGER, class_name TEXT NOT NULL, method_name TEXT NOT NULL, signature TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS results (export_index INTEGER PRIMARY KEY, status TEXT, body TEXT)")
        db.execute("DELETE FROM methods")
        db.execute("DELETE FROM results")
        db.execute("CREATE INDEX IF NOT EXISTS methods_class ON methods(class_name,id)")
        db.execute("CREATE INDEX IF NOT EXISTS methods_export ON methods(export_index)")
        for lib in libraries:
            directory = job / "native" / lib["key"]
            manifest = directory / "methods.tsv"
            if not manifest.is_file():
                continue
            db.execute("CREATE TEMP TABLE IF NOT EXISTS native_cache (address INTEGER PRIMARY KEY, status TEXT, body TEXT)")
            db.execute("DELETE FROM native_cache")
            result_file = directory / "results.tsv"
            if result_file.is_file():
                with result_file.open(encoding="utf-8", errors="replace") as results:
                    for line in results:
                        if not line.endswith("\n"):
                            continue
                        parts = line.rstrip("\n").split("\t")
                        if len(parts) == 3:
                            try:
                                db.execute("INSERT OR REPLACE INTO native_cache VALUES (?,?,?)",
                                           (int(parts[0], 16), parts[1], _decoded(parts[2])))
                            except (ValueError, UnicodeError):
                                continue  # Last append may have been interrupted.
            export_dir = job / "classes_c" / "native" / lib["key"]
            export_dir.mkdir(parents=True, exist_ok=True)
            for stale in export_dir.glob("functions_*.c"):
                stale.unlink()
            metadata_dir = job / "classes_metadata" / "native"
            metadata_dir.mkdir(parents=True, exist_ok=True)
            # Chunk exports to keep large stripped libraries usable in editors.
            writer = None
            try:
                with manifest.open(encoding="utf-8") as source, (metadata_dir / (lib["key"] + ".txt")).open("w", encoding="utf-8") as meta:
                    for line in source:
                        parts = line.rstrip("\n").split("\t")
                        if len(parts) != 5:
                            continue
                        index, address = int(parts[0]), int(parts[1], 16)
                        name, namespace, signature = map(_decoded, parts[2:])
                        total += 1
                        chunk = (index - 1) // 500 + 1
                        class_name = f"{lib['name']} / functions_{chunk:04d}"
                        db.execute("INSERT INTO methods VALUES (?,?,?,?,?,?)",
                                   (total, total, address, class_name, name, signature))
                        cached = db.execute("SELECT status,body FROM native_cache WHERE address=?", (address,)).fetchone()
                        status, body = cached or ("not_attempted", "")
                        if status == "ok" and not body.strip():
                            status = "empty"
                        db.execute("INSERT INTO results VALUES (?,?,?)", (total, status, body))
                        if status == "ok":
                            success += 1
                        elif pseudocode:
                            counts[status] = counts.get(status, 0) + 1
                            failures.append({"library": lib["name"], "method": name,
                                             "address": f"0x{address:X}", "status": status,
                                             "error": body[:2000]})
                        if (index - 1) % 500 == 0 or writer is None:
                            if writer:
                                writer.close()
                            writer = (export_dir / f"functions_{chunk:04d}.c").open("w", encoding="utf-8")
                            safe_library = lib['name'].replace('*/', '* /')
                            writer.write(f"/* Native library: {safe_library} | {lib['architecture']}\n"
                                         "   Reconstructed pseudocode; names/types may be inferred. */\n\n")
                        label = f"{namespace}::{name}" if namespace else name
                        label = label.replace("*/", "* /")
                        writer.write(f"/* {label} | Address: 0x{address:X} */\n")
                        writer.write(body + "\n\n" if status == "ok" else f"/* {status} */\n\n")
                        meta.write(f"0x{address:X}\t{label}\t{signature}\n")
            finally:
                if writer:
                    writer.close()
        with (job / "class_index.csv").open("w", encoding="utf-8-sig", newline="") as target:
            out = csv.writer(target)
            out.writerow(["class_name", "method_count"])
            out.writerows(db.execute("SELECT class_name,COUNT(*) FROM methods GROUP BY class_name"))
    analyzed = sum((job / "native" / lib["key"] / "analysis_ready").is_file() for lib in libraries)
    report = {"backend": "Ghidra Native", "pseudocode_enabled": pseudocode,
              "selected_for_decompile": total, "functions_with_body": success,
              "functions_without_body": len(failures), "failed_by_status": counts,
              "libraries_selected": len(libraries), "libraries_analyzed": analyzed,
              "partial": analyzed < len(libraries) or bool(failures) or total == 0}
    (job / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (job / "failed_functions.json").write_text(json.dumps({"count": len(failures), "functions": failures},
                                                          ensure_ascii=False, indent=2), encoding="utf-8")
    emit(f"Đã xuất native: {success:,}/{total:,} hàm có thân; "
         f"{analyzed}/{len(libraries)} thư viện đã phân tích. Kết quả: {job / 'classes_c' / 'native'}")
    return report
