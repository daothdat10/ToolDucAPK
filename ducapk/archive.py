from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import zipfile


@dataclass(frozen=True)
class MemberRef:
    archive: Path
    member: str
    size: int
    source: str


@dataclass(frozen=True)
class ExtractedPair:
    binary: Path
    metadata: Path
    architecture: str
    binary_source: str
    metadata_source: str


ARCHITECTURES = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")


def _architecture(name: str) -> str:
    normalized = name.replace("_", "-").lower()
    for architecture in ARCHITECTURES:
        if architecture in normalized:
            return architecture
    return "unknown"


def _extract_member(ref: MemberRef, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ref.archive) as archive:
        with archive.open(ref.member) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output, 1024 * 1024)


def extract_il2cpp_pair(inputs: list[Path], workdir: Path, emit) -> ExtractedPair:
    """Find a matching IL2CPP binary and metadata in APK/XAPK/split APK inputs."""
    workdir.mkdir(parents=True, exist_ok=True)
    split_dir = workdir / "split_apks"
    split_dir.mkdir(exist_ok=True)
    binaries: list[MemberRef | Path] = []
    metadata_files: list[MemberRef | Path] = []
    seen_archives: set[Path] = set()
    pending: list[tuple[Path, str, int]] = []

    for source in inputs:
        source = source.expanduser().resolve()
        if source.is_dir():
            for child in sorted(source.iterdir()):
                if child.suffix.lower() in {".apk", ".xapk", ".apks", ".zip"}:
                    pending.append((child, str(child), 0))
        elif source.is_file() and source.name.lower() == "libil2cpp.so":
            binaries.append(source)
        elif source.is_file() and source.name.lower() == "global-metadata.dat":
            metadata_files.append(source)
        elif source.is_file():
            pending.append((source, str(source), 0))
        else:
            raise FileNotFoundError(f"Không tìm thấy: {source}")

    split_number = 0
    while pending:
        archive_path, source_label, depth = pending.pop(0)
        if archive_path in seen_archives:
            continue
        seen_archives.add(archive_path)
        if not zipfile.is_zipfile(archive_path):
            raise ValueError(f"Không phải APK/XAPK hợp lệ: {archive_path}")
        emit(f"Đọc gói: {archive_path.name}")
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member_lower = info.filename.replace("\\", "/").lower()
                basename = member_lower.rsplit("/", 1)[-1]
                if basename == "libil2cpp.so":
                    binaries.append(MemberRef(archive_path, info.filename, info.file_size,
                                              source_label + "!" + info.filename))
                elif basename == "global-metadata.dat":
                    metadata_files.append(MemberRef(archive_path, info.filename, info.file_size,
                                                    source_label + "!" + info.filename))
                elif depth == 0 and basename.endswith(".apk"):
                    if info.file_size > 4 * 1024**3:
                        raise ValueError(f"APK lồng quá lớn: {info.filename}")
                    split_number += 1
                    nested = split_dir / f"split_{split_number:03d}.apk"
                    with archive.open(info) as source, nested.open("wb") as output:
                        shutil.copyfileobj(source, output, 1024 * 1024)
                    pending.append((nested, source_label + "!" + info.filename, depth + 1))

    if not binaries:
        raise ValueError("Không thấy libil2cpp.so. Hãy kéo XAPK hoặc tất cả split APK của cùng bản game.")
    if not metadata_files:
        raise ValueError("Không thấy global-metadata.dat. Hãy kéo XAPK hoặc APK chứa assets của cùng bản game.")

    def binary_rank(item: MemberRef | Path) -> tuple[int, int]:
        name = item.source if isinstance(item, MemberRef) else str(item)
        architecture = _architecture(name)
        return (ARCHITECTURES.index(architecture) if architecture in ARCHITECTURES else 99,
                -(item.size if isinstance(item, MemberRef) else item.stat().st_size))

    selected_binary = sorted(binaries, key=binary_rank)[0]
    selected_metadata = sorted(metadata_files,
                               key=lambda item: -(item.size if isinstance(item, MemberRef)
                                                  else item.stat().st_size))[0]
    binary_path = workdir / "libil2cpp.so"
    metadata_path = workdir / "global-metadata.dat"
    for selected, destination in ((selected_binary, binary_path),
                                  (selected_metadata, metadata_path)):
        if isinstance(selected, MemberRef):
            _extract_member(selected, destination)
        else:
            shutil.copy2(selected, destination)

    with metadata_path.open("rb") as source:
        magic = source.read(4)
    if magic != b"\xaf\x1b\xb1\xfa":
        raise ValueError("global-metadata.dat không có header IL2CPP hợp lệ; có thể đã mã hóa hoặc không cùng bản APK.")

    binary_source = selected_binary.source if isinstance(selected_binary, MemberRef) else str(selected_binary)
    metadata_source = selected_metadata.source if isinstance(selected_metadata, MemberRef) else str(selected_metadata)
    emit(f"Đã lấy {_architecture(binary_source)} libil2cpp.so và global-metadata.dat")
    return ExtractedPair(binary_path, metadata_path, _architecture(binary_source),
                         binary_source, metadata_source)
