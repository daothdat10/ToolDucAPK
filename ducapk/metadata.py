from __future__ import annotations

import base64
import csv
import hashlib
import json
from pathlib import Path
import re
import sqlite3


def iter_script_methods(script_json: Path):
    """Stream ScriptMethod objects without loading a large script.json into RAM."""
    decoder = json.JSONDecoder()
    marker = '"ScriptMethod"'
    with script_json.open("r", encoding="utf-8-sig") as source:
        buffer = ""
        while marker not in buffer:
            chunk = source.read(256 * 1024)
            if not chunk:
                raise ValueError("Il2CppDumper không tạo ScriptMethod trong script.json")
            buffer += chunk
            if len(buffer) > 2 * 1024 * 1024:
                buffer = buffer[-len(marker):]
        buffer = buffer[buffer.index(marker) + len(marker):]
        while "[" not in buffer:
            chunk = source.read(256 * 1024)
            if not chunk:
                raise ValueError("ScriptMethod không phải một mảng JSON")
            buffer += chunk
        buffer = buffer[buffer.index("[") + 1:]

        while True:
            buffer = buffer.lstrip(" \t\r\n,")
            if buffer.startswith("]"):
                return
            if not buffer:
                chunk = source.read(256 * 1024)
                if not chunk:
                    raise ValueError("script.json kết thúc giữa danh sách ScriptMethod")
                buffer += chunk
                continue
            try:
                item, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                chunk = source.read(256 * 1024)
                if not chunk:
                    raise ValueError("ScriptMethod bị lỗi hoặc script.json chưa ghi xong")
                buffer += chunk
                continue
            if isinstance(item, dict):
                yield item
            buffer = buffer[end:]


def class_file_name(name: str, digest_of: str | None = None) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip(" ._")[:85].strip(" ._") or "UnknownClass"
    digest = hashlib.sha1((digest_of or name).encode("utf-8")).hexdigest()[:10]
    return f"{safe}_{digest}"


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def iter_unmapped_dump_methods(dump_cs: Path):
    """Include generic/abstract declarations that have no native RVA in dump.cs."""
    namespace = ""
    class_name = None
    awaiting_method = False
    with dump_cs.open("r", encoding="utf-8-sig", errors="replace") as source:
        for line in source:
            stripped = line.strip()
            if stripped.startswith("// Namespace:"):
                namespace = stripped.split(":", 1)[1].strip()
                class_name = None
                awaiting_method = False
            elif "// TypeDefIndex:" in stripped:
                declaration = stripped.split("// TypeDefIndex:", 1)[0]
                match = re.search(r"\b(?:class|struct|interface|enum)\s+(.+)", declaration)
                if match:
                    name = match.group(1).split(" : ", 1)[0].strip()
                    class_name = f"{namespace}.{name}" if namespace else name
            elif stripped.startswith("// RVA: -1"):
                awaiting_method = True
            elif awaiting_method:
                if not stripped or stripped.startswith("[") or stripped.startswith("//"):
                    continue
                awaiting_method = False
                if class_name and "(" in stripped:
                    before = stripped.split("(", 1)[0].strip()
                    method_name = before.rsplit(" ", 1)[-1]
                    if method_name:
                        yield class_name, method_name, stripped


def build_metadata_index(script_json: Path, job_dir: Path, emit) -> dict:
    job_dir.mkdir(parents=True, exist_ok=True)
    database = job_dir / "methods.sqlite"
    manifest = job_dir / "methods.tsv"
    metadata_dir = job_dir / "classes_metadata"
    metadata_dir.mkdir(exist_ok=True)
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE IF NOT EXISTS methods ("
                       "id INTEGER PRIMARY KEY, export_index INTEGER, address INTEGER, "
                       "class_name TEXT NOT NULL, method_name TEXT NOT NULL, "
                       "signature TEXT NOT NULL)")
    connection.execute("DELETE FROM methods")
    connection.execute("CREATE INDEX IF NOT EXISTS methods_class ON methods(class_name, id)")
    connection.execute("CREATE INDEX IF NOT EXISTS methods_export ON methods(export_index)")
    total = 0
    mapped = 0
    batch = []
    with manifest.open("w", encoding="utf-8", newline="\n") as output:
        for item in iter_script_methods(script_json):
            total += 1
            address = int(item.get("Address") or 0)
            full_name = str(item.get("Name") or f"UnknownMethod_{total}")
            if "$$" in full_name:
                class_name, method_name = full_name.split("$$", 1)
            else:
                class_name, method_name = "Native.Unmapped", full_name
            signature = str(item.get("Signature") or "")
            export_index = None
            if address > 0:
                mapped += 1
                export_index = mapped
                output.write(f"{mapped}\t{address}\t{_b64(class_name)}\t"
                             f"{_b64(method_name)}\t{_b64(signature)}\n")
            batch.append((total, export_index, address, class_name, method_name, signature))
            if len(batch) >= 2000:
                connection.executemany("INSERT INTO methods VALUES (?,?,?,?,?,?)", batch)
                connection.commit()
                batch.clear()
            if total % 10000 == 0:
                emit(f"Đã đọc metadata: {total:,} phương thức")
        if batch:
            connection.executemany("INSERT INTO methods VALUES (?,?,?,?,?,?)", batch)
            connection.commit()
            batch.clear()

    unmapped = 0
    dump_cs = script_json.with_name("dump.cs")
    if dump_cs.is_file():
        for class_name, method_name, signature in iter_unmapped_dump_methods(dump_cs):
            total += 1
            unmapped += 1
            batch.append((total, None, 0, class_name, method_name, signature))
            if len(batch) >= 2000:
                connection.executemany("INSERT INTO methods VALUES (?,?,?,?,?,?)", batch)
                connection.commit()
                batch.clear()
        if batch:
            connection.executemany("INSERT INTO methods VALUES (?,?,?,?,?,?)", batch)
            connection.commit()
        emit(f"Đã thêm {unmapped:,} khai báo không có địa chỉ native từ dump.cs")

    classes = 0
    current_name = None
    current_file = None
    current_writer = None
    with (job_dir / "class_index.csv").open("w", encoding="utf-8-sig", newline="") as index_file:
        index_writer = csv.writer(index_file)
        index_writer.writerow(("class_name", "metadata_file"))
        try:
            cursor = connection.execute(
                "SELECT class_name, method_name, signature, address "
                "FROM methods ORDER BY class_name, id")
            for class_name, method_name, signature, address in cursor:
                if class_name != current_name:
                    if current_writer is not None:
                        current_writer.close()
                    current_name = class_name
                    current_file = metadata_dir / (class_file_name(class_name) + ".txt")
                    current_writer = current_file.open("w", encoding="utf-8")
                    current_writer.write(f"CLASS: {class_name}\n\n")
                    index_writer.writerow((class_name, str(current_file.relative_to(job_dir))))
                    classes += 1
                current_writer.write(f"0x{address:X}  {method_name}\n")
                if signature:
                    current_writer.write(f"    {signature}\n")
        finally:
            if current_writer is not None:
                current_writer.close()
            connection.close()

    summary = {"methods": total, "mapped_methods": mapped, "classes": classes,
               "unmapped_methods": total - mapped}
    (job_dir / "metadata_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    emit(f"Đã nhóm {total:,} phương thức vào {classes:,} class; "
         f"{mapped:,} phương thức có địa chỉ native")
    return summary


def build_cpp2il_metadata_index(method_map: Path, job_dir: Path, emit) -> dict:
    """Build the same browser/index files from Cpp2IL's supported-version RVA map."""
    job_dir.mkdir(parents=True, exist_ok=True)
    database = job_dir / "methods.sqlite"
    manifest = job_dir / "methods.tsv"
    metadata_dir = job_dir / "classes_metadata"
    metadata_dir.mkdir(exist_ok=True)
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE IF NOT EXISTS methods ("
                       "id INTEGER PRIMARY KEY, export_index INTEGER, address INTEGER, "
                       "class_name TEXT NOT NULL, method_name TEXT NOT NULL, "
                       "signature TEXT NOT NULL)")
    connection.execute("DELETE FROM methods")
    connection.execute("CREATE INDEX IF NOT EXISTS methods_class ON methods(class_name, id)")
    connection.execute("CREATE INDEX IF NOT EXISTS methods_export ON methods(export_index)")
    total = mapped = 0
    batch = []
    with method_map.open("r", encoding="utf-8-sig", newline="") as source, \
            manifest.open("w", encoding="utf-8", newline="\n") as output:
        header = source.readline().strip().split("\t")
        if header != ["rva", "class_b64", "method_b64", "signature_b64"]:
            raise ValueError("Cpp2IL không tạo được bảng class/hàm DucAPK hợp lệ.")
        for line in source:
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) != 4:
                continue
            try:
                address = int(parts[0])
                class_name = base64.b64decode(parts[1]).decode("utf-8", errors="replace")
                method_name = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                signature = base64.b64decode(parts[3]).decode("utf-8", errors="replace")
            except (ValueError, UnicodeError):
                continue
            total += 1
            export_index = None
            if address > 0:
                mapped += 1
                export_index = mapped
                output.write(f"{mapped}\t{address}\t{_b64(class_name)}\t"
                             f"{_b64(method_name)}\t{_b64(signature)}\n")
            batch.append((total, export_index, address, class_name, method_name, signature))
            if len(batch) >= 2000:
                connection.executemany("INSERT INTO methods VALUES (?,?,?,?,?,?)", batch)
                connection.commit()
                batch.clear()
            if total % 10000 == 0:
                emit(f"Đã lập chỉ mục Cpp2IL: {total:,} phương thức")
        if batch:
            connection.executemany("INSERT INTO methods VALUES (?,?,?,?,?,?)", batch)
            connection.commit()
            batch.clear()

    classes = 0
    current_name = current_writer = None
    metadata_dir.mkdir(exist_ok=True)
    with (job_dir / "class_index.csv").open("w", encoding="utf-8-sig", newline="") as index_file:
        index_writer = csv.writer(index_file)
        index_writer.writerow(("class_name", "metadata_file"))
        try:
            cursor = connection.execute(
                "SELECT class_name, method_name, signature, address "
                "FROM methods ORDER BY class_name, id")
            for class_name, method_name, signature, address in cursor:
                if class_name != current_name:
                    if current_writer is not None:
                        current_writer.close()
                    current_name = class_name
                    target = metadata_dir / (class_file_name(class_name) + ".txt")
                    current_writer = target.open("w", encoding="utf-8")
                    current_writer.write(f"CLASS: {class_name}\n\n")
                    index_writer.writerow((class_name, str(target.relative_to(job_dir))))
                    classes += 1
                current_writer.write(f"0x{address:X}  {method_name}\n")
                if signature:
                    current_writer.write(f"    {signature}\n")
        finally:
            if current_writer is not None:
                current_writer.close()
    connection.close()
    summary = {"methods": total, "mapped_methods": mapped, "classes": classes,
               "unmapped_methods": total - mapped, "parser": "Cpp2IL"}
    (job_dir / "metadata_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    emit(f"Cpp2IL đã nhóm {total:,} phương thức vào {classes:,} class; "
         f"{mapped:,} phương thức có địa chỉ native")
    return summary
