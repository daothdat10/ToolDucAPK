"""Package the installed, tested Windows runtimes for a versioned GitHub Release.

Maintainer utility; requires Python 3.12 x64 and preinstalled tools. No credentials
or APK analysis outputs are included. Source snapshots preserve local tool changes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def add_tree(archive, source, prefix, excludes=()):
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_file() and not any(part in excludes for part in relative.parts):
            archive.write(path, (Path(prefix) / relative).as_posix())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--ghidra-zip", required=True, type=Path)
    parser.add_argument("--jdk-zip", required=True, type=Path)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12) or sys.platform != "win32":
        raise SystemExit("Build with Windows x64 Python 3.12 (wheel compatibility).")
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    runtime = output / f"ducapk-{args.tag}.zip"
    with zipfile.ZipFile(runtime, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in ("Il2CppDumper", "Cpp2IL", "jadx", "wheels"):
            add_tree(archive, ROOT / "tools" / name, "tools/" + name,
                     excludes=("__pycache__", ".git"))
        dotnet = ROOT / "tools" / "dotnet"
        for path in dotnet.iterdir():
            if path.is_file():
                archive.write(path, "tools/dotnet/" + path.name)
        for name in ("host", "shared"):
            add_tree(archive, dotnet / name, "tools/dotnet/" + name)
        python = Path(sys.base_prefix)
        for path in python.iterdir():
            if path.is_file() and path.name != "NEWS.txt":
                archive.write(path, "tools/python/" + path.name)
        for name in ("DLLs", "Lib", "tcl"):
            add_tree(archive, python / name, "tools/python/" + name,
                     excludes=("site-packages", "__pycache__", "test", "tests"))
        for name in ("Cpp2IL-src", "Il2CppDumper-next-src"):
            archive.write(ROOT / "tools" / name / "LICENSE", "tools/licenses/" + name + "-LICENSE.txt")
        archive.write(ROOT / "THIRD_PARTY.md", "tools/licenses/THIRD_PARTY.md")
    print(f"Packaged {runtime.name}: {runtime.stat().st_size / 1024**2:.1f} MB", flush=True)

    sources = output / f"ducapk-tool-sources-{args.tag}.zip"
    allowed = {".cs", ".csproj", ".sln", ".props", ".targets", ".md", ".txt", ".json", ".resx", ".xml", ".config", ".yml", ".yaml"}
    provenance = {}
    with zipfile.ZipFile(sources, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("Cpp2IL-src", "Il2CppDumper-next-src"):
            repo = ROOT / "tools" / name
            provenance[name] = {"commit": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
                                "origin": subprocess.check_output(["git", "-C", str(repo), "remote", "get-url", "origin"], text=True).strip()}
            for path in sorted(repo.rglob("*")):
                relative = path.relative_to(repo)
                if (path.is_file() and not any(part in {".git", "bin", "obj", "TestFiles", "packages"} for part in relative.parts)
                        and (path.suffix.lower() in allowed or path.name in {"LICENSE", ".gitignore", ".gitmodules"})):
                    archive.write(path, (Path(name) / relative).as_posix())
        archive.writestr("provenance.json", json.dumps(provenance, indent=2))
    print(f"Packaged source snapshots: {sources.stat().st_size / 1024**2:.1f} MB", flush=True)
    base = f"https://github.com/daothdat10/ToolDucAPK/releases/download/{args.tag}/"
    assets = []
    for path, target, required in [
        (runtime, ".", ["tools/python/python.exe", "tools/python/pythonw.exe", "tools/python/Lib/venv/__init__.py",
                        "tools/Il2CppDumper/Il2CppDumper.exe", "tools/Cpp2IL/Cpp2IL.dll", "tools/dotnet/dotnet.exe",
                        "tools/jadx/bin/jadx.bat", "tools/wheels"]),
        (args.ghidra_zip, "tools/ghidra", ["tools/ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat"]),
        (args.jdk_zip, "tools/jdk", ["tools/jdk/jdk-25.0.4.1+1/bin/java.exe"]),
    ]:
        assets.append({"name": path.name, "url": base + path.name, "sha256": digest(path),
                       "size": path.stat().st_size, "unpack_to": target, "required": required})
    manifest = {"schema_version": 1, "release_tag": args.tag, "platform": "windows-x64",
                "python_version": sys.version.split()[0], "assets": assets,
                "source_snapshot": {"name": sources.name, "url": base + sources.name, "sha256": digest(sources)}}
    (ROOT / "runtime-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Wrote runtime-manifest.json", flush=True)


if __name__ == "__main__":
    main()
