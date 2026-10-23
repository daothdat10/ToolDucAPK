"""Resolve portable runtimes, optional local overrides and existing installations."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent


def resolve_toolchain(root: Path = ROOT, environ=None) -> dict[str, Path]:
    env = os.environ if environ is None else environ
    config_file = root / "tool_paths.json"
    config = json.loads(config_file.read_text(encoding="utf-8-sig")) if config_file.is_file() else {}

    def choose(key, candidates, marker=None):
        override = env.get("DUCAPK_" + key.upper()) or config.get(key)
        if override:
            path = Path(override).expanduser()
            return path if path.is_absolute() else root / path
        options = [Path(path) for path in candidates if path]
        for path in options:
            if (path / marker if marker else path).is_file():
                return path
        return options[0]

    tools = root / "tools"
    ghidras = sorted((tools / "ghidra").glob("ghidra_*"), reverse=True)
    jdks = sorted((tools / "jdk").glob("jdk*"), reverse=True)
    java_exe = shutil.which("java", path=env.get("PATH", ""))
    return {
        "il2cpp_dir": choose("il2cpp_dir", [tools / "Il2CppDumper"], "Il2CppDumper.exe"),
        "cpp2il": choose("cpp2il", [tools / "Cpp2IL" / "Cpp2IL.dll"]),
        "dotnet": choose("dotnet", [tools / "dotnet" / "dotnet.exe", shutil.which("dotnet", path=env.get("PATH", ""))]),
        "jadx": choose("jadx", [tools / "jadx" / "bin" / "jadx.bat"]),
        "ghidra": choose("ghidra", [tools / "ghidra", *ghidras, env.get("GHIDRA_HOME"),
                                    Path(r"D:\ghidra\ghidra_12.1.4_PUBLIC")], "support/analyzeHeadless.bat"),
        "java_home": choose("java_home", [tools / "jdk", *jdks, env.get("JAVA_HOME"),
                                          Path(java_exe).parent.parent if java_exe else None,
                                          Path(r"D:\ghidra\jdk-25.0.4.1+1")], "bin/java.exe"),
    }


def check_toolchain(root: Path = ROOT) -> bool:
    markers = {"il2cpp_dir": "Il2CppDumper.exe", "ghidra": "support/analyzeHeadless.bat",
               "java_home": "bin/java.exe"}
    complete = True
    for key, path in resolve_toolchain(root).items():
        target = path / markers[key] if key in markers else path
        present = target.is_file()
        complete &= present
        print(f"{'OK' if present else 'MISSING'} {key}: {path}")
    if not complete:
        print("Run Setup.bat to install the portable runtimes.")
    return complete


if __name__ == "__main__":
    raise SystemExit(0 if check_toolchain() else 1)
