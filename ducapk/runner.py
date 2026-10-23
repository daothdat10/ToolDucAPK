from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import sqlite3
import subprocess
import threading
import time
import zipfile

from .archive import extract_il2cpp_pair
from .categories import ALL_CATEGORIES, CATEGORY_DIRS, CATEGORY_LABELS, category_for_class
from .assemblies import assembly_report, package_name, resolver_for_job
from .eta import ProgressEta, finish_clock, format_duration
from .layout import ClassLayout
from .metadata import build_cpp2il_metadata_index, build_metadata_index, class_file_name
from .toolchain import resolve_toolchain


ROOT = Path(__file__).resolve().parent.parent
_toolchain = resolve_toolchain()
TOOLS = _toolchain["il2cpp_dir"]
CPP2IL = _toolchain["cpp2il"]
DOTNET = _toolchain["dotnet"]
GHIDRA = _toolchain["ghidra"]
JAVA_HOME = _toolchain["java_home"]
JADX = _toolchain["jadx"]
BATCH_SIZE = 1000
# Most IL2CPP methods decompile in well under a second; the few that hit the
# timeout dominate total runtime, so the first pass gives up early and only
# those methods get one longer retry.
FIRST_PASS_TIMEOUT_SECONDS = 10
RETRY_TIMEOUTS_SECONDS = (60,)
DEFAULT_GHIDRA_THREADS = max(1, min(16, (os.cpu_count() or 2) - 2))
ghidra_threads = DEFAULT_GHIDRA_THREADS


def set_ghidra_threads(count: int):
    """Set how many decompiler workers each Ghidra run uses."""
    global ghidra_threads
    ghidra_threads = max(1, int(count))


def _metadata_path(job: Path, emit=None) -> Path:
    """Return validated IL2CPP metadata, recovering supported XOR wrappers.

    Some Unity titles leave the metadata magic/version intact but XOR the section
    table and heaps with a short key embedded in libil2cpp.so. Keep the extracted
    original untouched and only use a sidecar if its complete section table
    validates after the transform.
    """
    source = job / "input" / "global-metadata.dat"
    data = source.read_bytes()
    binary = job / "input" / "libil2cpp.so"

    def valid_metadata(blob: bytes) -> bool:
        if len(blob) < 8 + 32 * 8 or blob[:4] != b"\xaf\x1b\xb1\xfa":
            return False
        version = int.from_bytes(blob[4:8], "little")
        if version < 16 or version > 31:
            return False
        size = len(blob)
        pairs = []
        for pos in range(8, 8 + 32 * 8, 8):
            offset = int.from_bytes(blob[pos:pos + 4], "little")
            length = int.from_bytes(blob[pos + 4:pos + 8], "little")
            if offset == 0 and length == 0:
                continue
            if offset > size or length > size or offset + length > size:
                return False
            pairs.append((offset, length))
        # In IL2CPP metadata the first data section follows the fixed header.
        return bool(pairs and pairs[0][0] == 0x100 and len(pairs) >= 24)

    # Inline-key format used by Il2cppEncrtypt: the first 1024 bytes are plain,
    # followed by a descriptor, `kl` uint32 key words, then DWORD-wise XOR data.
    # The descriptor's low 16 bits hold kl; bytes above that field are ignored.
    # When the original size is not DWORD-aligned, the encoder still XORs the
    # final partial word but only writes its leading bytes, so those tail bytes
    # are restored with the low (little-endian) bytes of the matching key word.
    # Validate the decoded metadata before accepting a possible false positive.
    safe_size = 1024
    descriptor_size = 4
    if len(data) >= safe_size + descriptor_size:
        key_length = int.from_bytes(data[safe_size:safe_size + 2], "little")
        if 130 <= key_length <= 140:
            key_start = safe_size + descriptor_size
            payload_start = key_start + key_length * 4
            payload = data[payload_start:]
            if payload:
                key_words = [
                    int.from_bytes(data[pos:pos + 4], "little")
                    for pos in range(key_start, payload_start, 4)
                ]
                decoded = bytearray(data[:safe_size])
                for pos in range(0, len(payload), 4):
                    key_index = (pos + (pos // key_length)) % key_length
                    chunk = payload[pos:pos + 4]
                    word = int.from_bytes(chunk, "little") ^ key_words[key_index]
                    decoded.extend(word.to_bytes(4, "little")[:len(chunk)])
                result = bytes(decoded)
                if valid_metadata(result) and b"Assembly-CSharp" in result:
                    target = job / "recovered_il2cpp" / "global-metadata.decrypted.dat"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if not target.is_file() or target.read_bytes() != result:
                        target.write_bytes(result)
                    if emit:
                        emit("Đã nhận diện XOR metadata kiểu Il2cppEncrtypt "
                             f"(khóa nhúng, kl={key_length}); đã xác thực header "
                             f"và lưu sidecar: {target}")
                    return target

    # Check this after the inline-key probe: this format preserves the metadata
    # header, so its encrypted file can still pass header-only validation.
    if valid_metadata(data):
        return source

    # Known obfuscation used by an earlier supplied build. Require the marker
    # in the matching native library and validate the complete metadata header.
    key = b"dbtxijk\x00"
    if not binary.is_file() or binary.read_bytes().find(key) < 0:
        return source
    decoded = bytearray(data)
    for index in range(8, len(decoded)):
        decoded[index] ^= key[(index - 8) % len(key)]
    result = bytes(decoded)
    if not valid_metadata(result) or b"Assembly-CSharp" not in result:
        return source
    target = job / "recovered_il2cpp" / "global-metadata.decrypted.dat"
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.is_file() or target.read_bytes() != result:
        target.write_bytes(result)
    if emit:
        emit("Đã nhận diện XOR metadata của Fruit Pick Puzzle; "
             f"đã xác thực 32 mục header và lưu sidecar: {target}")
    return target


def _json_safe(value):
    """Make nested strings safe for UTF-8 JSON/log output."""
    if isinstance(value, str):
        return "".join("\ufffd" if 0xD800 <= ord(char) <= 0xDFFF else char
                       for char in value)
    if isinstance(value, dict):
        return {_json_safe(str(key)): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return value


_GENERIC_ARGS = re.compile(r"(?<=[\w\]])<[^<>]*>")


def _generic_definition(name: str) -> str:
    """Strip generic arguments: ComponentPool<Foo>.Bar<Baz> -> ComponentPool.Bar.

    Compiler-generated names such as <Start>b__0 or <>c are left untouched.
    """
    previous = None
    while previous != name:
        previous, name = name, _GENERIC_ARGS.sub("", name)
    return name


def _build_scope_manifest(job: Path, included_categories: set[str]) -> tuple[Path, int, dict[str, int], int]:
    """Keep the full metadata index while creating a compact, stable decompile list.

    IL2CPP emits one native copy per generic instantiation (ComponentPool<A>,
    ComponentPool<B>, ...). They share the same logic, so only the first copy of
    each generic method is decompiled; the rest count as skipped by scope.
    """
    source = job / "methods.tsv"
    target = job / "methods.selected.tsv"
    database = job / "methods.sqlite"
    counts = {key: 0 for key in CATEGORY_LABELS}
    selected_count = 0
    generic_seen = set()
    generic_skipped = 0
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE IF NOT EXISTS selected_methods ("
                       "export_index INTEGER PRIMARY KEY, category TEXT NOT NULL)")
    connection.execute("DELETE FROM selected_methods")
    resolver = resolver_for_job(job, connection)
    batch = []
    with source.open("r", encoding="utf-8") as src, \
            target.open("w", encoding="utf-8", newline="\n") as out:
        for line in src:
            fields = line.rstrip("\r\n").split("\t")
            if len(fields) != 5:
                continue
            try:
                export_index = int(fields[0])
                class_name = base64.b64decode(fields[2]).decode("utf-8", errors="replace")
                method_name = base64.b64decode(fields[3]).decode("utf-8", errors="replace")
                signature = base64.b64decode(fields[4]).decode("utf-8", errors="replace")
            except (ValueError, UnicodeError):
                continue
            category = resolver.category(class_name)
            if category not in included_categories:
                continue
            definition = (_generic_definition(class_name), _generic_definition(method_name))
            if definition != (class_name, method_name):
                key = (*definition, signature.count(","))
                if key in generic_seen:
                    generic_skipped += 1
                    continue
                generic_seen.add(key)
            selected_count += 1
            counts[category] += 1
            # Work index is dense; result index still addresses the full metadata database.
            out.write(f"{selected_count}\t{export_index}\t" + "\t".join(fields[1:]) + "\n")
            batch.append((export_index, category))
            if len(batch) >= 2000:
                connection.executemany("INSERT OR REPLACE INTO selected_methods VALUES (?,?)", batch)
                connection.commit()
                batch.clear()
    if batch:
        connection.executemany("INSERT OR REPLACE INTO selected_methods VALUES (?,?)", batch)
        connection.commit()
    assembly_report(job, connection, resolver)
    connection.close()
    return target, selected_count, counts, generic_skipped


def _emit_assembly_summary(job: Path, emit):
    """Log which assemblies were treated as game, SDK or Unity (details in assemblies.json)."""
    path = job / "assemblies.json"
    if not path.is_file():
        return
    rows = json.loads(path.read_text(encoding="utf-8"))["assemblies"]
    for category in ("game", "sdk", "unity"):
        totals: dict[str, int] = {}
        for row in rows:
            if row["category"] == category:
                totals[row["assembly"]] = totals.get(row["assembly"], 0) + row["native_methods"]
        if totals:
            top = sorted(totals.items(), key=lambda item: -item[1])
            shown = ", ".join(f"{name} ({count:,})" for name, count in top[:8])
            more = f" và {len(top) - 8} assembly khác" if len(top) > 8 else ""
            emit(f"Assembly → {CATEGORY_LABELS[category]}: {shown}{more}")
    emit(f"Chi tiết phân loại theo assembly: {path}")


class AnalysisCancelled(Exception):
    pass


def _state(job: Path, **changes):
    path = job / "job.json"
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    data.update(changes)
    if changes.get("status") in {"created", "extracting", "metadata", "decompiling", "decompiling_java", "grouping",
                                  "retrying", "complete", "metadata_complete"}:
        data.pop("error", None)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(_json_safe(data), ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def _job_logger(job: Path, emit):
    downstream = emit
    log_path = job / "activity.log"

    def write(message: str):
        text = _json_safe(str(message))
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"[{stamp}] {text}\n")
        downstream(text)

    return write


def _apk_inputs(inputs: list[Path], job: Path) -> list[Path]:
    """Return directly selected APKs plus nested split APKs extracted by archive.py."""
    direct: list[Path] = []
    for source in inputs:
        source = source.expanduser().resolve()
        if source.is_dir():
            direct.extend(p for p in sorted(source.iterdir()) if p.suffix.lower() == ".apk")
        elif source.suffix.lower() == ".apk":
            direct.append(source)
    nested = sorted((job / "input" / "split_apks").glob("*.apk"))
    chosen = nested or direct
    return list(dict.fromkeys(path for path in chosen if path.is_file()))


def _run_jadx(inputs: list[Path], job: Path, emit,
              cancel: threading.Event, required: bool) -> tuple[bool, int, int]:
    apks = _apk_inputs(inputs, job)
    if not apks:
        if required:
            raise ValueError("Gói này không có IL2CPP và không tìm thấy APK/split APK để đọc DEX.")
        return False, 0, 0
    if not JADX.is_file():
        if required:
            raise FileNotFoundError(f"Thiếu JADX: {JADX}")
        return False, 0, 0
    output = job / "java_source"
    source_output = output / "sources"
    source_count = (sum(1 for _ in source_output.rglob("*.java"))
                    if source_output.is_dir() else 0)
    if source_count:
        emit("Đã có kết quả JADX; dùng lại.")
        previous_log = job / "jadx.log"
        prior_errors = 0
        if previous_log.is_file():
            match = re.search(r"finished with errors, count:\s*(\d+)",
                              previous_log.read_text(encoding="utf-8", errors="replace"))
            if match:
                prior_errors = int(match.group(1))
        return True, 1 if prior_errors else 0, source_count
    source_output.mkdir(parents=True, exist_ok=True)
    emit(f"JADX: giải mã DEX/Java/Kotlin từ {len(apks)} APK/split...")
    env = _java_environment()
    env["JADX_CACHE_DIR"] = str(job / "jadx_cache")
    env["JADX_TMP_DIR"] = str(job / "jadx_tmp")
    env["JAVA_TOOL_OPTIONS"] = "-Xmx6g"
    command = ["cmd.exe", "/d", "/c", str(JADX), "--show-bad-code", "--no-res",
               "--threads-count", "3", "--output-dir-src", str(source_output), *map(str, apks)]
    code = _process(command, ROOT, env, job / "jadx.log", emit, cancel)
    source_count = (sum(1 for _ in source_output.rglob("*.java"))
                    if source_output.exists() else 0)
    if source_count == 0:
        if required:
            raise RuntimeError("JADX không tạo được source DEX. Xem jadx.log; APK có thể bị bảo vệ/đóng gói tùy biến.")
        emit("Cảnh báo: JADX không xuất được phần Java; xem jadx.log.")
        return False, code, 0
    if code != 0:
        emit(f"JADX xuất {source_count:,} file Java nhưng có lỗi một số class; xem jadx.log.")
    return True, code, source_count


def _process(command: list[str], cwd: Path, env: dict[str, str],
             log_file: Path, emit, cancel: threading.Event) -> int:
    lines: queue.Queue[str | None] = queue.Queue()
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    with log_file.open("a", encoding="utf-8") as log:
        log.write("COMMAND: " + subprocess.list2cmdline(command) + "\n")
        log.flush()
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                errors="replace", bufsize=1, creationflags=flags)

        def read_output():
            try:
                for line in proc.stdout:
                    lines.put(line)
            finally:
                lines.put(None)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        stream_done = False
        while not stream_done or proc.poll() is None:
            if cancel.is_set():
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                   capture_output=True, check=False)
                else:
                    proc.terminate()
                raise AnalysisCancelled("Đã dừng; kết quả theo từng lô vẫn được giữ lại.")
            try:
                line = lines.get(timeout=0.25)
            except queue.Empty:
                continue
            if line is None:
                stream_done = True
                continue
            log.write(line)
            if any(word in line for word in ("DUCAPK_PROGRESS", "DUCAPK_CURRENT",
                                             "DUCAPK_BATCH_DONE")):
                emit(line.strip())
                if "DUCAPK_PROGRESS " in line:
                    _report_eta(line, emit)
            elif any(word in line for word in ("ERROR", "Exception", "Dumping", "Finished")):
                emit(line.strip()[:500])
        log.flush()
        return proc.wait()


_decompile_eta = ProgressEta()
ETA_LOG_EVERY = 1000


def _reset_eta():
    global _decompile_eta
    _decompile_eta = ProgressEta()


def _report_eta(line: str, emit):
    """Every ETA_LOG_EVERY functions, log speed and the estimated finish of this pass."""
    match = re.search(r"DUCAPK_PROGRESS (\d+)/(\d+)", line)
    if not match:
        return
    current, total = int(match.group(1)), int(match.group(2))
    previous = _decompile_eta.samples[-1][1] if _decompile_eta.samples else None
    _decompile_eta.update(current, total, time.monotonic())
    if previous is None or (current // ETA_LOG_EVERY == previous // ETA_LOG_EVERY and current != total):
        return
    remaining = _decompile_eta.remaining_seconds()
    elapsed = format_duration(_decompile_eta.elapsed_seconds(time.monotonic()))
    if remaining is None:
        emit(f"ETA: {current:,}/{total:,} hàm, đã chạy {elapsed}; chưa đủ dữ liệu đo tốc độ.")
        return
    emit(f"ETA: {current:,}/{total:,} hàm · {_decompile_eta.rate():.1f} hàm/s (5 phút gần nhất) · "
         f"đã chạy {elapsed} · còn ~{format_duration(remaining)}, xong ~{finish_clock(remaining)} "
         "(chưa gồm vòng retry và bước xuất file).")


def _java_environment() -> dict[str, str]:
    env = os.environ.copy()
    env["JAVA_HOME"] = str(JAVA_HOME)
    env["PATH"] = str(JAVA_HOME / "bin") + os.pathsep + env.get("PATH", "")
    env["GHIDRA_HEADLESS_MAXMEM"] = "6G"
    return env


def _project_dir(job: Path) -> Path:
    # Ghidra rejects punctuation such as '+' in project path elements.
    key = hashlib.sha1(str(job.resolve()).encode("utf-8")).hexdigest()[:16]
    return ROOT / "projects" / f"job_{key}"


def _detect_unity_version(job: Path) -> str | None:
    pattern = re.compile(rb"(?:20\d{2}|6000)\.\d+\.\d+[abfp]\d+")
    unity_data_candidates: list[tuple[Path, str]] = []
    for apk in sorted((job / "input" / "split_apks").glob("*.apk")):
        try:
            with zipfile.ZipFile(apk) as archive:
                for info in archive.infolist():
                    name = info.filename.lower()
                    if info.file_size > 64 * 1024 * 1024:
                        continue
                    if "globalgamemanagers" in name and info.file_size <= 2 * 1024 * 1024:
                        match = pattern.search(archive.read(info))
                        if match:
                            return match.group().decode("ascii")
                    # Some split APKs omit globalgamemanagers but retain Unity's
                    # serialized data bundle, which carries the engine version.
                    if name.endswith("/bin/data/data.unity3d") or name == "data.unity3d":
                        unity_data_candidates.append((apk, info.filename))
        except (OSError, zipfile.BadZipFile):
            continue
    for apk, member in unity_data_candidates:
        try:
            import UnityPy
            with zipfile.ZipFile(apk) as archive:
                env = UnityPy.load(archive.read(member))
            for file_obj in env.files.values():
                versions = [getattr(file_obj, "version_engine", None)]
                versions.extend(getattr(child, "unity_version", None)
                                for child in getattr(file_obj, "files", {}).values())
                for version in versions:
                    if version and pattern.fullmatch(str(version).encode("ascii", errors="ignore")):
                        return str(version)
        except Exception:
            continue
    return None


def _run_cpp2il(job: Path, emit, cancel: threading.Event,
                metadata_path: Path | None = None) -> Path:
    if not CPP2IL.is_file() or not DOTNET.is_file():
        raise FileNotFoundError("Parser metadata mới chưa được cài trong tools/Cpp2IL.")
    unity_version = _detect_unity_version(job)
    if unity_version is None:
        raise RuntimeError("Il2CppDumper không hỗ trợ metadata này và không tìm được "
                           "phiên bản Unity trong globalgamemanagers hoặc data.unity3d "
                           "để chạy Cpp2IL.")
    output = job / "cpp2il_map"
    method_map = output / "ducapk_methods.tsv"
    if method_map.is_file() and method_map.stat().st_size > 100:
        emit(f"Đã có bảng Cpp2IL cho Unity {unity_version}; dùng lại.")
        return method_map
    output.mkdir(exist_ok=True)
    command = [str(DOTNET), str(CPP2IL),
               "--force-binary-path", str(job / "input" / "libil2cpp.so"),
               "--force-metadata-path", str(metadata_path or _metadata_path(job, emit)),
               "--force-unity-version", unity_version,
               "--output-as", "ducapk-map", "--output-to", str(output),
               "--low-memory-mode"]
    emit(f"Il2CppDumper không hỗ trợ metadata; dùng Cpp2IL cho Unity {unity_version}...")
    env = os.environ.copy()
    env["DOTNET_ROOT"] = str(DOTNET.parent)
    code = _process(command, ROOT, env, job / "cpp2il.log", emit, cancel)
    if code != 0 or not method_map.is_file():
        raise RuntimeError("Cpp2IL chưa đọc được metadata/binary. Xem cpp2il.log; "
                           "gói này có thể dùng biến thể metadata chưa hỗ trợ.")
    return method_map


def _run_dumper(job: Path, emit, cancel: threading.Event) -> tuple[str, Path]:
    executable = TOOLS / "Il2CppDumper.exe"
    output = job / "il2cppdumper"
    output.mkdir(exist_ok=True)
    metadata_path = _metadata_path(job, emit)
    metadata_bytes = metadata_path.read_bytes()
    metadata_size = len(metadata_bytes)
    version_bytes = metadata_bytes[:8]
    if len(version_bytes) < 8 or version_bytes[:4] != b"\xaf\x1b\xb1\xfa":
        raise ValueError("Metadata không có magic IL2CPP hợp lệ; có thể bị mã hóa hoặc bị cắt.")
    version = int.from_bytes(version_bytes[4:8], "little")

    # The magic/version can remain intact even when a game's loader has encrypted
    # or rewritten the section table. Catch clearly impossible offsets before
    # sending the same bytes through multiple parsers and reporting a vague EOF.
    header = metadata_bytes[8:8 + 8 * 8]
    invalid_sections = 0
    for offset in range(0, len(header) - 7, 8):
        section_offset = int.from_bytes(header[offset:offset + 4], "little")
        section_size = int.from_bytes(header[offset + 4:offset + 8], "little")
        if section_offset == 0 and section_size == 0:
            continue
        if (section_offset > metadata_size or section_size > metadata_size or
                section_offset + section_size > metadata_size):
            invalid_sections += 1
    if invalid_sections >= 2:
        raise ValueError(
            f"global-metadata.dat có magic/version IL2CPP {version}, nhưng "
            f"{invalid_sections}/8 bảng đầu có offset/size vượt kích thước file "
            f"({metadata_size:,} byte). Metadata nhiều khả năng đã bị game mã hóa/"
            "obfuscate hoặc không khớp với libil2cpp.so. Il2CppDumper/Cpp2IL không "
            "thể đọc trực tiếp dạng này; cần metadata đã giải mã hoặc logic/khóa "
            "giải mã riêng của game. Phần JADX fallback chỉ xuất Java/Kotlin, "
            "không khôi phục được mã IL2CPP/native."
        )
    if version > 31 or version < 16:
        method_map = _run_cpp2il(job, emit, cancel, metadata_path)
        return "Cpp2IL", method_map
    if metadata_path != job / "input" / "global-metadata.dat":
        emit("Metadata đã được khôi phục; dùng Cpp2IL trực tiếp để tránh kết quả "
             "không đáng tin từ Il2CppDumper với biến thể đã obfuscate.")
        method_map = _run_cpp2il(job, emit, cancel, metadata_path)
        return "Cpp2IL", method_map
    if not executable.is_file():
        raise FileNotFoundError(f"Thiếu Il2CppDumper: {executable}")
    if (output / "script.json").is_file() and (output / "dump.cs").is_file():
        emit("Đã có kết quả Il2CppDumper; dùng lại.")
        return "Il2CppDumper", output / "script.json"
    emit("Đang lấy tên class, phương thức và địa chỉ từ IL2CPP metadata...")
    code = _process([str(executable), str(job / "input" / "libil2cpp.so"),
                     str(metadata_path), str(output)],
                    TOOLS, os.environ.copy(), job / "dumper.log", emit, cancel)
    if code != 0 or not (output / "script.json").is_file():
        method_map = _run_cpp2il(job, emit, cancel, metadata_path)
        return "Cpp2IL", method_map
    return "Il2CppDumper", output / "script.json"


def _headless(job: Path, args: list[str], log_file: Path, emit,
              cancel: threading.Event) -> int:
    launcher = GHIDRA / "support" / "analyzeHeadless.bat"
    if not launcher.is_file() or not (JAVA_HOME / "bin" / "java.exe").is_file():
        raise FileNotFoundError("Thiếu Ghidra hoặc JDK. Chạy Setup.bat hoặc cấu hình tool_paths.json.")
    project_dir = _project_dir(job)
    project_dir.mkdir(parents=True, exist_ok=True)
    command = [str(launcher), str(project_dir), "DucAPK", *args]
    env = _java_environment()
    env["DUCAPK_GHIDRA_THREADS"] = str(ghidra_threads)
    env["DUCAPK_METHOD_INDEX"] = str(job / "methods.tsv")
    return _process(command, ROOT, env, log_file, emit, cancel)


_GHIDRA_HEADER_TYPEDEFS = """typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef long long intptr_t;
typedef unsigned long long uintptr_t;
typedef unsigned long long size_t;
typedef _Bool bool;
"""


def _prepare_ghidra_metadata(job: Path) -> Path | None:
    """Turn Il2CppDumper output into inputs for DucAPKApplyMetadata.java.

    Returns None when the job has no il2cpp.h/script.json (e.g. the Cpp2IL path).
    """
    dumper = job / "il2cppdumper"
    header, script = dumper / "il2cpp.h", dumper / "script.json"
    if not header.is_file() or not script.is_file():
        return None
    meta = job / "ghidra_meta"
    meta.mkdir(exist_ok=True)
    # Ghidra's C parser has no "struct A : B" inheritance; embed the base as a field.
    text = header.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r": (\w+) {", r"{\n \1 super;", text)
    (meta / "il2cpp_ghidra.h").write_text(_GHIDRA_HEADER_TYPEDEFS + text, encoding="utf-8")
    del text

    def b64(value: str) -> str:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")

    data = json.loads(script.read_text(encoding="utf-8"))
    with (meta / "strings.tsv").open("w", encoding="utf-8", newline="\n") as out:
        for item in data.get("ScriptString", []):
            out.write(f"{item['Address']}\t{b64(item['Value'])}\n")
    with (meta / "metadata.tsv").open("w", encoding="utf-8", newline="\n") as out:
        for item in data.get("ScriptMetadata", []):
            out.write(f"{item['Address']}\t{b64(item['Name'])}\t{b64(item.get('Signature') or '')}\n")
        for item in data.get("ScriptMetadataMethod", []):
            out.write(f"{item['Address']}\t{b64(item['Name'])}\t\n")
    return meta


def _apply_ghidra_metadata(job: Path, emit, cancel: threading.Event):
    """Load il2cpp.h types, method names/signatures, strings and TypeInfo once per job."""
    done = job / "ghidra_meta" / "applied.ok"
    if done.is_file():
        return
    meta = _prepare_ghidra_metadata(job)
    if meta is None:
        emit("Ghidra: không có il2cpp.h/script.json; giữ pseudocode không có tên field.")
        return
    emit("Ghidra: nạp il2cpp.h + script.json (tên hàm, kiểu tham số, field, chuỗi)... "
         "bước này chạy một lần mỗi job, có thể mất vài phút.")
    code = _headless(job, ["-process", "libil2cpp.so", "-noanalysis",
                           "-scriptPath", str(ROOT / "scripts"),
                           "-postScript", "DucAPKApplyMetadata.java",
                           str(meta), str(job / "methods.tsv")],
                     job / "ghidra_metadata.log", emit, cancel)
    log_path = job / "ghidra_metadata.log"
    log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    if code != 0 or "DUCAPK_META_DONE" not in log:
        emit("Ghidra: nạp metadata thất bại (xem ghidra_metadata.log); tiếp tục giải mã không có tên field.")
        return
    done.write_text(datetime.now().isoformat(), encoding="utf-8")


def _run_ghidra(job: Path, mapped_methods: int, emit,
                cancel: threading.Event, max_methods: int | None):
    project = _project_dir(job) / "DucAPK.gpr"
    if not project.is_file():
        emit("Ghidra: nhập libil2cpp.so, bỏ qua Auto Analyze toàn cục...")
        code = _headless(job, ["-import", str(job / "input" / "libil2cpp.so"),
                               "-noanalysis"], job / "ghidra_import.log", emit, cancel)
        if code != 0 or not project.is_file():
            raise RuntimeError("Ghidra không nhập được libil2cpp.so; xem ghidra_import.log")
    _apply_ghidra_metadata(job, emit, cancel)

    limit = min(mapped_methods, max_methods) if max_methods else mapped_methods
    manifest = job / "methods.selected.tsv"
    if not manifest.is_file():
        manifest = job / "methods.tsv"
    batch_dir = job / "batches"
    batch_dir.mkdir(exist_ok=True)
    _reset_eta()
    for start in range(1, limit + 1, BATCH_SIZE):
        if cancel.is_set():
            raise AnalysisCancelled("Đã dừng tại ranh giới lô.")
        end = min(start + BATCH_SIZE - 1, limit)
        result = batch_dir / f"batch_{start:07d}_{end:07d}.tsv"
        existing = set()
        if result.is_file():
            with result.open("r", encoding="utf-8") as source:
                for line in source:
                    try:
                        existing.add(int(line.split("\t", 1)[0]))
                    except ValueError:
                        pass
        if len(existing) >= end - start + 1:
            emit(f"Bỏ qua lô đã xong {start:,}–{end:,}")
            continue
        emit(f"Ghidra: giải mã hàm {start:,}–{end:,} / {limit:,}")
        code = _headless(job, ["-process", "libil2cpp.so", "-noanalysis",
                               "-scriptPath", str(ROOT / "scripts"),
                               "-postScript", "DucAPKDecompile.java",
                               str(manifest), str(result), str(start), str(end),
                               str(FIRST_PASS_TIMEOUT_SECONDS), "decompile", str(limit)],
                         job / f"ghidra_{start:07d}.log", emit, cancel)
        if code != 0:
            raise RuntimeError(f"Ghidra dừng ở lô {start:,}–{end:,}. "
                               "Chạy lại cùng job sẽ tiếp tục từ kết quả đã ghi.")
        completed = set()
        if result.is_file():
            with result.open("r", encoding="utf-8") as source:
                for line in source:
                    try:
                        completed.add(int(line.split("\t", 1)[0]))
                    except ValueError:
                        pass
        if len(completed) < end - start + 1:
            raise RuntimeError(f"Ghidra chưa ghi xong lô {start:,}–{end:,}; "
                               "xem ghidra_*.log và dùng Tiếp tục job.")
        _state(job, processed_native=end, native_total=limit)


def _failed_native_rows(job: Path, limit: int) -> list[tuple[int, list[str]]]:
    """Return selected manifest rows whose result is missing or has no C body."""
    database = job / "methods.sqlite"
    connection = sqlite3.connect(database)
    try:
        statuses = {int(export_index): (status, body) for export_index, status, body in connection.execute(
            "SELECT export_index, status, body FROM results")}
    finally:
        connection.close()

    manifest = job / "methods.selected.tsv"
    if not manifest.is_file():
        manifest = job / "methods.tsv"
    failed = []
    with manifest.open("r", encoding="utf-8") as source:
        for line in source:
            fields = line.rstrip("\r\n").split("\t")
            if len(fields) == 6:
                work_index, export_index = int(fields[0]), int(fields[1])
                payload = fields[2:]
            elif len(fields) == 5:
                work_index = export_index = int(fields[0])
                payload = fields[1:]
            else:
                continue
            if work_index > limit:
                break
            status, body = statuses.get(export_index, (None, ""))
            if status != "ok" or not (body or "").strip():
                failed.append((export_index, payload))
    return failed


def _retry_missing_bodies(job: Path, limit: int, emit,
                          cancel: threading.Event) -> dict:
    """Retry non-OK native methods with longer timeouts, then keep partial jobs partial."""
    report = _collect_results(job, emit)
    batch_dir = job / "batches"
    prior_attempts = []
    for path in batch_dir.glob("batch_zretry_*.tsv"):
        match = re.search(r"batch_zretry_(\d+)\.tsv$", path.name)
        if match:
            prior_attempts.append(int(match.group(1)))
    attempt_number = max(prior_attempts, default=0) + 1
    for retry_index, timeout in enumerate(RETRY_TIMEOUTS_SECONDS):
        round_number = attempt_number + retry_index
        failed = _failed_native_rows(job, limit)
        if not failed:
            break
        if cancel.is_set():
            raise AnalysisCancelled("Đã dừng trước vòng thử lại hàm lỗi.")

        retry_dir = job / "retry"
        retry_dir.mkdir(exist_ok=True)
        manifest = retry_dir / f"methods_retry_{round_number:04d}.tsv"
        result = batch_dir / f"batch_zretry_{round_number:04d}.tsv"
        with manifest.open("w", encoding="utf-8", newline="\n") as output:
            for work_index, (export_index, payload) in enumerate(failed, 1):
                output.write(f"{work_index}\t{export_index}\t" + "\t".join(payload) + "\n")

        _reset_eta()
        emit(f"Ghidra retry lượt {retry_index + 1}/{len(RETRY_TIMEOUTS_SECONDS)} "
             f"(lần #{round_number}): thử {len(failed):,} hàm chưa có thân, "
             f"timeout {timeout}s mỗi hàm...")
        _state(job, status="retrying", retry_round=round_number,
               retry_pending=len(failed), retry_timeout_seconds=timeout)
        code = _headless(job, ["-process", "libil2cpp.so", "-noanalysis",
                               "-scriptPath", str(ROOT / "scripts"),
                               "-postScript", "DucAPKDecompile.java",
                               str(manifest), str(result), "1", str(len(failed)),
                               str(timeout), "decompile", str(limit),
                               str(max(0, limit - len(failed)))],
                         job / f"ghidra_retry_{round_number:04d}.log", emit, cancel)
        if cancel.is_set():
            raise AnalysisCancelled("Đã dừng trong khi thử lại các hàm lỗi.")
        report = _collect_results(job, emit)
        remaining = len(_failed_native_rows(job, limit))
        recovered = len(failed) - remaining
        emit(f"Vòng retry {round_number}: lấy thêm {recovered:,}; còn thiếu {remaining:,}.")
        _state(job, retry_exit_code=code, retry_pending=remaining)
        if code != 0 or recovered == 0:
            emit("Ghidra không lấy thêm được thân hàm ở vòng này; job sẽ không được đánh dấu hoàn tất.")
            break
    return report


def retry_failed_only(job: Path, emit, cancel: threading.Event) -> dict:
    """Retry only selected methods without a non-empty pseudocode body in an existing job."""
    job = job.expanduser().resolve()
    state_path = job / "job.json"
    if not state_path.is_file() or not (job / "methods.sqlite").is_file():
        raise ValueError("Chọn thư mục job Ghidra có job.json và methods.sqlite.")
    info = json.loads(state_path.read_text(encoding="utf-8"))
    if info.get("backend") == "Ghidra Native":
        analyze([], job.parent, emit, cancel, resume_job=job)
        return json.loads((job / "report.json").read_text(encoding="utf-8"))
    if not info.get("with_ghidra", True):
        raise ValueError("Job này không chạy Ghidra nên không có pseudocode để thử lại.")
    emit = _job_logger(job, emit)
    selected = int(info.get("selected_native_methods", 0))
    limit = min(int(info.get("native_total", selected) or selected), selected) if selected else 0
    if limit <= 0:
        raise ValueError("Job chưa có danh sách hàm Ghidra để thử lại.")

    emit(f"Job: {job}")
    report = _collect_results(job, emit)
    failed_before = len(_failed_native_rows(job, limit))
    if failed_before == 0:
        final = "complete" if report["functions_without_body"] == 0 else "partial"
        _state(job, status=final, report=report, last_retry_count=0)
        emit(f"Không còn hàm lỗi trong phạm vi đã chạy: có thân "
             f"{report['functions_with_body']:,}/{report['selected_for_decompile']:,}; "
             f"còn thiếu thân {report['functions_without_body']:,} hàm.")
        emit(f"Kết quả class đã xuất tại: {job / 'classes_c'}")
        return report

    emit(f"Bắt đầu truy xuất riêng {failed_before:,} hàm chưa có thân; các hàm đã xuất thành công sẽ được bỏ qua.")
    _state(job, status="retrying", retry_pending=failed_before)
    report = _retry_missing_bodies(job, limit, emit, cancel)
    failed_after = len(_failed_native_rows(job, limit))
    recovered = max(0, failed_before - failed_after)
    final_status = "complete" if report["functions_without_body"] == 0 else "partial"
    _state(job, status=final_status, report=report,
           last_retry_count=failed_before, last_retry_recovered=recovered,
           last_retry_remaining=failed_after,
           last_retry_at=datetime.now().isoformat())
    emit(f"KẾT QUẢ THỬ LẠI: phục hồi {recovered:,}/{failed_before:,}; còn lỗi {failed_after:,} hàm.")
    emit(f"Đã cập nhật pseudocode/class tại: {job / 'classes_c'}")
    if failed_after:
        emit(f"Danh sách hàm còn lỗi: {job / 'failed_functions.json'}")
    return report


def _remove_stale_class_files(class_dir: Path, written: set[Path]):
    """Drop generated .c files from an older layout or scope, then prune empty folders."""
    # rglob("*.c") is case-insensitive on Windows and also yields folders such as
    # a namespace truncated to "...View.C", so only remove regular files.
    for path in class_dir.rglob("*.c"):
        if path.is_file() and path not in written:
            path.unlink()
    for folder in sorted((p for p in class_dir.rglob("*") if p.is_dir()),
                         key=lambda p: len(p.parts), reverse=True):
        if not any(folder.iterdir()):
            folder.rmdir()


def _collect_results(job: Path, emit) -> dict:
    if (job / "native_libraries.json").is_file():
        from .native import collect_native_results
        return collect_native_results(job, emit)
    database = job / "methods.sqlite"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE IF NOT EXISTS results ("
                       "export_index INTEGER PRIMARY KEY, status TEXT, body TEXT)")
    for batch in sorted((job / "batches").glob("batch_*.tsv")) if (job / "batches").exists() else []:
        with batch.open("r", encoding="utf-8") as source:
            rows = []
            for line in source:
                parts = line.rstrip("\r\n").split("\t", 2)
                if len(parts) != 3:
                    continue
                try:
                    index = int(parts[0])
                    body = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                except (ValueError, UnicodeError):
                    continue
                rows.append((index, parts[1], body))
                if len(rows) >= 500:
                    connection.executemany("INSERT OR REPLACE INTO results VALUES (?,?,?)", rows)
                    connection.commit()
                    rows.clear()
            if rows:
                connection.executemany("INSERT OR REPLACE INTO results VALUES (?,?,?)", rows)
                connection.commit()

    class_dir = job / "classes_c"
    class_dir.mkdir(exist_ok=True)
    job_info = json.loads((job / "job.json").read_text(encoding="utf-8"))
    included_categories = set(job_info.get("included_categories", ALL_CATEGORIES))
    class_names = [name for (name,) in connection.execute("SELECT DISTINCT class_name FROM methods")]
    layouts = {category: ClassLayout(class_names, group_global_by_role=category == "game")
               for category in included_categories}
    resolver = resolver_for_job(job, connection)
    current_name = None
    writer = None
    class_count = 0
    written: set[Path] = set()
    try:
        cursor = connection.execute(
            "SELECT m.export_index, m.class_name, m.method_name, m.signature, m.address, "
            "r.status, r.body FROM methods m LEFT JOIN results r "
            "ON m.export_index = r.export_index ORDER BY m.class_name, m.id")
        for export_index, class_name, method_name, signature, address, status, body in cursor:
            category = resolver.category(class_name)
            if category not in included_categories:
                continue
            if class_name != current_name:
                if writer is not None:
                    writer.close()
                current_name = class_name
                target = (class_dir / CATEGORY_DIRS[category] /
                          layouts[category].relative_path(class_name, ".c"))
                if len(str(target)) > 240:  # stay under the Windows MAX_PATH limit
                    target = class_dir / CATEGORY_DIRS[category] / (class_file_name(class_name) + ".c")
                target.parent.mkdir(parents=True, exist_ok=True)
                written.add(target)
                writer = target.open("w", encoding="utf-8")
                writer.write("/* IL2CPP class: " + class_name.replace("*/", "* /") + " */\n\n")
                class_count += 1
            writer.write("/* " + method_name.replace("*/", "* /") +
                         f" | RVA: 0x{address:X}\n")
            if signature:
                writer.write("   " + signature.replace("*/", "* /") + "\n")
            writer.write("*/\n")
            if status == "ok" and body:
                writer.write(body + "\n\n")
            else:
                explanation = status or ("no native address" if not address else "not decompiled yet")
                writer.write("/* " + explanation.replace("*/", "* /") + " */\n\n")
    finally:
        if writer is not None:
            writer.close()
    _remove_stale_class_files(class_dir, written)

    counts = dict(connection.execute(
        "SELECT status, COUNT(*) FROM results GROUP BY status").fetchall())
    total = connection.execute("SELECT COUNT(*) FROM methods").fetchone()[0]
    mapped = connection.execute("SELECT COUNT(*) FROM methods WHERE export_index IS NOT NULL").fetchone()[0]
    has_selection = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='selected_methods'").fetchone()
    selected = (connection.execute("SELECT COUNT(*) FROM selected_methods").fetchone()[0]
                if has_selection else mapped)
    if has_selection:
        successful_selected = connection.execute(
            "SELECT COUNT(*) FROM selected_methods s JOIN results r "
            "ON r.export_index=s.export_index WHERE r.status='ok' AND TRIM(r.body)<>''"
        ).fetchone()[0]
    else:
        successful_selected = connection.execute(
            "SELECT COUNT(*) FROM results WHERE status='ok' AND TRIM(body)<>''"
        ).fetchone()[0]
    if has_selection:
        failed_rows = connection.execute(
            "SELECT m.export_index,m.class_name,m.method_name,m.signature,m.address,"
            "r.status,r.body FROM selected_methods s "
            "JOIN methods m ON m.export_index=s.export_index "
            "LEFT JOIN results r ON r.export_index=m.export_index "
            "WHERE r.status IS NULL OR r.status<>'ok' OR TRIM(COALESCE(r.body,''))='' "
            "ORDER BY m.id").fetchall()
    pseudocode_enabled = bool(job_info.get("with_ghidra", True))
    if not pseudocode_enabled:
        failed_rows = []
    else:
        failed_rows = connection.execute(
            "SELECT m.export_index,m.class_name,m.method_name,m.signature,m.address,"
            "r.status,r.body FROM methods m LEFT JOIN results r "
            "ON r.export_index=m.export_index "
            "WHERE m.export_index IS NOT NULL AND "
            "(r.status IS NULL OR r.status<>'ok' OR TRIM(COALESCE(r.body,''))='') "
            "ORDER BY m.id").fetchall()
    connection.close()
    failed_by_status: dict[str, int] = {}
    failed_details = []
    for export_index, class_name, method_name, signature, address, status, body in failed_rows:
        label = ("empty" if status == "ok" and not (body or "").strip()
                 else status or "not_attempted")
        failed_by_status[label] = failed_by_status.get(label, 0) + 1
        failed_details.append({
            "export_index": export_index,
            "class": class_name,
            "method": method_name,
            "signature": signature,
            "address": f"0x{address:X}" if address else "0x0",
            "status": label,
            "error": (body or "")[:2000],
        })
    summary = {"methods_in_metadata": total, "mapped_native_methods": mapped,
               "classes_written": class_count, "decompile_results": counts,
               "selected_for_decompile": selected,
               "pseudocode_enabled": pseudocode_enabled,
               "functions_with_body": successful_selected,
               "functions_without_body": len(failed_rows),
               "failed_by_status": failed_by_status,
               "skipped_by_scope": mapped - selected,
               "not_decompiled": max(0, selected - sum(counts.values()))}
    (job / "report.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                     encoding="utf-8")
    (job / "failed_functions.json").write_text(
        json.dumps({"count": len(failed_details), "by_status": failed_by_status,
                    "functions": failed_details}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    if pseudocode_enabled:
        emit(f"Đã xuất {class_count:,} file class; có thân pseudocode: "
             f"{successful_selected:,}/{selected:,}; còn thiếu thân: {len(failed_rows):,}.")
    else:
        emit(f"Đã xuất metadata của {class_count:,} class; chưa chạy Ghidra theo cấu hình job.")
    if failed_by_status:
        emit("Phân loại hàm chưa có thân: " + ", ".join(
            f"{name}={count:,}" for name, count in sorted(failed_by_status.items())))
        emit(f"Danh sách chi tiết: {job / 'failed_functions.json'}")
    return summary


def _analyze_native(inputs, job, emit, cancel, with_ghidra, max_methods,
                    include_categories, decompile_java):
    from .native import discover_native_libraries, collect_native_results
    _state(job, backend="Ghidra Native", apk_type="Native C/C++", status="extracting")
    try:
        libraries = discover_native_libraries(_apk_inputs(inputs, job), job,
                                              include_categories, emit, cancel)
    except InterruptedError as error:
        raise AnalysisCancelled(str(error)) from error
    emit("Ghidra Native: tự tìm hàm trong ELF; tên class/hàm và kiểu dữ liệu có thể không còn tên gốc.")
    emit("Nhóm Logic game/SDK dựa theo tên thư viện; nhóm Unity/.NET chỉ áp dụng cho IL2CPP.")
    for lib in libraries:
        if cancel.is_set():
            raise AnalysisCancelled("Đã dừng; tiếp tục job để xử lý phần native còn lại.")
        directory = job / "native" / lib["key"]
        binary = job / lib["binary"]
        ready = directory / "analysis_ready"
        reuse = ready.is_file() and (_project_dir(directory) / "DucAPK.gpr").is_file()
        arguments = (["-process", binary.name, "-noanalysis"] if reuse else
                     ["-import", str(binary), "-overwrite"])
        (directory / "script_complete").unlink(missing_ok=True)
        _state(job, status="decompiling", native_library=lib["name"])
        emit(f"Ghidra Native: {lib['name']} — " +
             ("tiếp tục các hàm chưa có thân." if reuse else "nhập ELF và Auto Analyze để tìm hàm…"))
        # Native C++ needs Auto Analyze, unlike metadata-mapped IL2CPP functions.
        code = _headless(directory, [*arguments, "-max-cpu", str(ghidra_threads),
                         "-scriptPath", str(ROOT / "scripts"), "-postScript", "DucAPKNative.java",
                         str(directory), str(max_methods or 0), str(with_ghidra).lower()],
                         directory / "ghidra_native.log", emit, cancel)
        if code != 0 or not (directory / "methods.tsv").is_file() or not (directory / "script_complete").is_file():
            raise RuntimeError(f"Ghidra chưa xử lý xong {lib['name']}; xem {directory / 'ghidra_native.log'}")
        ready.touch()
        collect_native_results(job, emit)
    java_partial = False
    if decompile_java:
        _, exit_code, sources = _run_jadx(inputs, job, emit, cancel, required=False)
        java_partial = exit_code != 0
        _state(job, jadx_exit_code=exit_code, jadx_java_sources=sources)
    report = collect_native_results(job, emit)
    report["partial"] = report["partial"] or java_partial
    (job / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    status = "partial" if report["partial"] else "complete" if with_ghidra else "metadata_complete"
    _state(job, status=status, report=report)
    emit(f"Xong: {job}")
    return job


def analyze(inputs: list[Path], output_root: Path, emit, cancel: threading.Event,
            with_ghidra: bool = True, max_methods: int | None = None,
            resume_job: Path | None = None,
            include_categories: set[str] | None = None,
            extract_levels: bool = True, decompile_java: bool = True,
            decompile_native: bool = False) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    if resume_job:
        job = resume_job.resolve()
        if not (job / "job.json").is_file():
            raise ValueError("Thư mục này không phải job DucAPK đã tạo trước đó.")
        saved_info = json.loads((job / "job.json").read_text(encoding="utf-8"))
        saved_categories = set(saved_info.get("included_categories", ALL_CATEGORIES))
        if include_categories is not None and include_categories != saved_categories:
            raise ValueError("Lựa chọn phần mã của job đã lưu không khớp; tiếp tục job dùng cấu hình cũ.")
        include_categories = saved_categories
        extract_levels = bool(saved_info.get("extract_levels", extract_levels))
        decompile_java = bool(saved_info.get("decompile_java", decompile_java))
        decompile_native = bool(saved_info.get("decompile_native", decompile_native))
        if saved_info.get("backend") == "Ghidra Native":
            with_ghidra = bool(saved_info.get("with_ghidra", True))
        if not inputs:
            inputs = [Path(p) for p in saved_info.get("inputs", [])]
        _state(job, with_ghidra=with_ghidra)
        # The persistent logger is bound after the job directory has been resolved.
    else:
        include_categories = set(include_categories or {"game"})
        invalid = include_categories - ALL_CATEGORIES
        if invalid:
            raise ValueError(f"Nhóm decompile không hợp lệ: {', '.join(sorted(invalid))}")
        if with_ghidra and not include_categories:
            raise ValueError("Chọn ít nhất một nhóm class để tạo pseudocode.")
        stem = re.sub(r"[^A-Za-z0-9_-]+", "_", inputs[0].stem).strip("_")[:45] or "APK"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        job = output_root / f"{stem}_{stamp}"
        job.mkdir(parents=True, exist_ok=False)
        _state(job, status="created", inputs=[str(p) for p in inputs],
               created_at=datetime.now().isoformat(), with_ghidra=with_ghidra,
               included_categories=sorted(include_categories),
               extract_levels=extract_levels, decompile_java=decompile_java,
               decompile_native=decompile_native)

    emit = _job_logger(job, emit)
    if resume_job:
        emit(f"Tiếp tục job: {job}")

    try:
        if (job / "native_libraries.json").is_file():
            return _analyze_native(inputs, job, emit, cancel, with_ghidra,
                                   max_methods, include_categories, decompile_java)
        pair = None
        if not (job / "input" / "libil2cpp.so").is_file():
            _state(job, status="extracting")
            try:
                pair = extract_il2cpp_pair(inputs, job / "input", emit)
            except ValueError as error:
                message = str(error)
                if not (message.startswith("Không thấy libil2cpp.so") or
                        message.startswith("Không thấy global-metadata.dat")):
                    raise
                if decompile_native:
                    return _analyze_native(inputs, job, emit, cancel, with_ghidra,
                                           max_methods, include_categories, decompile_java)
                if extract_levels:
                    from .levels import LevelScanCancelled, extract_level_json
                    try:
                        extract_level_json(_apk_inputs(inputs, job), job, emit, cancel)
                    except LevelScanCancelled as stopped:
                        raise AnalysisCancelled(str(stopped)) from stopped
                if not decompile_java:
                    _state(job, status="levels_only", apk_type="Android DEX (Java/Kotlin)")
                    emit(f"APK không có Unity IL2CPP; bỏ qua JADX theo yêu cầu. Xong: {job}")
                    return job
                _state(job, status="decompiling_java", backend="JADX",
                       apk_type="Android DEX (Java/Kotlin)")
                _, jadx_exit, java_sources = _run_jadx(inputs, job, emit, cancel, required=True)
                summary = {"backend": "JADX", "java_sources": java_sources,
                           "jadx_exit_code": jadx_exit,
                           "partial": jadx_exit != 0}
                (job / "report.json").write_text(
                    json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
                _state(job, status="partial" if jadx_exit else "complete",
                       backend="JADX", report=summary,
                       java_source=str(job / "java_source"))
                if jadx_exit:
                    emit(f"JADX xong một phần: {java_sources:,} file Java đã xuất; xem jadx.log để biết class bị lỗi.")
                emit(f"Xong JADX: {job / 'java_source'}")
                return job
        if pair is not None:
            _state(job, binary_source=pair.binary_source,
                   metadata_source=pair.metadata_source, architecture=pair.architecture,
                   apk_type="Unity IL2CPP")
        _state(job, il2cpp_workflow="il2cpp_metadata_then_ghidra_pseudocode")
        emit("Kiến thức lõi IL2CPP đang áp dụng: ghép libil2cpp.so với global-metadata.dat; "
             "chọn Il2CppDumper hoặc Cpp2IL theo phiên bản/kết quả đọc metadata; "
             "dùng Ghidra để tạo pseudocode native từ các địa chỉ đã ánh xạ.")
        if extract_levels:
            from .levels import LevelScanCancelled, extract_level_json
            try:
                extract_level_json(_apk_inputs(inputs, job), job, emit, cancel)
            except LevelScanCancelled as stopped:
                raise AnalysisCancelled(str(stopped)) from stopped
        if cancel.is_set():
            raise AnalysisCancelled("Đã dừng.")
        _state(job, status="metadata")
        try:
            parser_name, parser_output = _run_dumper(job, emit, cancel)
        except Exception as native_error:
            if extract_levels:
                try:
                    from .levels import annotate_level_mechanics
                    annotate_level_mechanics(job, emit)
                except Exception as annotation_error:
                    emit(f"Không thể gắn tên mechanic vào JSON level: {annotation_error}")
            if not decompile_java:
                _state(job, status="partial", native_error=str(native_error))
                emit(f"Không đọc được metadata IL2CPP: {native_error}. Giữ phần level đã trích.")
                return job
            emit(f"Không đọc được metadata IL2CPP: {native_error}. Thử lấy phần DEX bằng JADX...")
            try:
                jadx_ok, jadx_exit, java_sources = _run_jadx(
                    inputs, job, emit, cancel, required=False)
            except Exception:
                raise native_error
            if not jadx_ok:
                raise native_error
            summary = {"backend": "JADX fallback", "java_sources": java_sources,
                       "jadx_exit_code": jadx_exit, "partial": True,
                       "native_error": str(native_error)}
            (job / "report.json").write_text(
                json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
            _state(job, status="partial", backend="JADX fallback",
                   native_error=str(native_error), report=summary,
                   java_source=str(job / "java_source"))
            emit(f"Đã giữ phần Java/Kotlin: {java_sources:,} file; phần IL2CPP cần parser phù hợp.")
            return job
        if extract_levels:
            from .flatbuffers_levels import extract_flatbuffer_levels
            from .levels import LevelScanCancelled
            try:
                extract_flatbuffer_levels(_apk_inputs(inputs, job), job, emit, cancel)
            except LevelScanCancelled as stopped:
                raise AnalysisCancelled(str(stopped)) from stopped
            except Exception as flatbuffer_error:
                emit(f"Không giải mã được level FlatBuffers: {flatbuffer_error}")
            try:
                from .levels import annotate_level_mechanics
                annotate_level_mechanics(job, emit)
            except Exception as annotation_error:
                emit(f"Không thể gắn tên mechanic vào JSON level: {annotation_error}")
            try:
                from .level_editor import ensure_cpp2il_types
                from .levels import annotate_level_field_names
                ensure_cpp2il_types(job, emit, cancel)
                annotate_level_field_names(job, emit)
            except Exception as rename_error:
                emit(f"Không thể đổi tên trường viết tắt trong JSON level: {rename_error}")
        summary_path = job / "metadata_summary.json"
        summary = (json.loads(summary_path.read_text(encoding="utf-8"))
                   if summary_path.is_file() else build_metadata_index(
                       parser_output, job, emit) if parser_name == "Il2CppDumper" else
                   build_cpp2il_metadata_index(parser_output, job, emit))
        _state(job, metadata_parser=parser_name)
        if not json.loads((job / "job.json").read_text(encoding="utf-8")).get("package_name"):
            _state(job, package_name=package_name(_apk_inputs(inputs, job)))
        try:
            jadx_ok, jadx_exit, java_sources = (_run_jadx(inputs, job, emit, cancel, required=False)
                                                if decompile_java else (False, 0, 0))
            if jadx_ok and jadx_exit:
                _state(job, jadx_exit_code=jadx_exit, jadx_java_sources=java_sources)
        except (OSError, RuntimeError) as error:
            _state(job, jadx_error=str(error))
            emit(f"Cảnh báo: không giải mã được phần Java/Android: {error}")
        if with_ghidra:
            _, selected_methods, category_counts, generic_skipped = _build_scope_manifest(
                job, include_categories)
            if selected_methods == 0:
                raise ValueError("Không có hàm native nào trong các nhóm đã chọn.")
            emit("Nhóm được chọn: " + ", ".join(
                f"{CATEGORY_LABELS[key]} ({category_counts[key]:,})"
                for key in sorted(include_categories)))
            _emit_assembly_summary(job, emit)
            if generic_skipped:
                emit(f"Bỏ qua {generic_skipped:,} bản sao generic trùng logic "
                     "(chỉ giải mã một bản cho mỗi hàm generic).")
            emit(f"Ghidra sẽ decompile {selected_methods:,}/{summary['mapped_methods']:,} hàm native.")
            _state(job, status="decompiling", native_total=selected_methods,
                   selected_native_methods=selected_methods,
                   category_method_counts=category_counts)
            _run_ghidra(job, selected_methods, emit, cancel, max_methods)
        _state(job, status="grouping")
        report = _collect_results(job, emit)
        if with_ghidra:
            _state(job, status="retrying")
            report = _retry_missing_bodies(job, min(selected_methods,
                                                    max_methods or selected_methods),
                                           emit, cancel)
        final = ("metadata_complete" if not with_ghidra else
                 "complete" if report["functions_without_body"] == 0 else "partial")
        _state(job, status=final, report=report)
        emit(f"Xong: {job}")
        return job
    except AnalysisCancelled:
        _state(job, status="cancelled")
        if (job / "methods.sqlite").exists() or (job / "native_libraries.json").is_file():
            _collect_results(job, emit)
        raise
    except Exception as error:
        _state(job, status="failed", error=str(error))
        if (job / "methods.sqlite").exists() or (job / "native_libraries.json").is_file():
            _collect_results(job, emit)
        raise
