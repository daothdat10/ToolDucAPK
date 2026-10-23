"""Best-effort translator for Ghidra C pseudocode to unsafe C# reference code.

Input `.c` files are read only. The translator handles common Ghidra C forms,
including integer aliases and direct IL2CPP field reads/writes. It reports
unsupported native constructs instead of claiming the result is equivalent.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


_CLASS_RE = re.compile(r"^/\*\s*IL2CPP class:\s*(.*?)\s*\*/", re.MULTILINE)
_METHOD_RE = re.compile(
    r"^/\*\s*([^\r\n]*?)\s*\|\s*RVA:\s*(0x[0-9A-Fa-f]+)[^\r\n]*\r?\n(.*?)\r?\n\*/",
    re.MULTILINE | re.DOTALL,
)
_FUNCTION_RE = re.compile(
    r"(?m)^\s*(?P<ret>(?:const\s+)?[\w.$<>]+(?:\s*\*)*)\s+"
    r"(?P<name>[A-Za-z_$][\w.$]*)\s*\((?P<params>[^;{}]*)\)\s*\{"
)
_CS_TYPES = {
    "void": "void", "bool": "bool", "char": "sbyte", "byte": "byte",
    "sbyte": "sbyte", "short": "short", "ushort": "ushort", "int": "int",
    "uint": "uint", "long": "long", "ulong": "ulong", "float": "float",
    "double": "double",
    "undefined": "byte", "undefined1": "byte", "undefined2": "ushort",
    "undefined4": "uint", "undefined8": "ulong", "undefined16": "UInt128",
    "undefined *": "byte*", "undefined1 *": "byte*", "undefined2 *": "ushort*",
    "undefined4 *": "uint*", "undefined8 *": "ulong*", "undefined16 *": "UInt128*",
    "int8_t": "sbyte", "uint8_t": "byte", "int16_t": "short", "uint16_t": "ushort",
    "int32_t": "int", "uint32_t": "uint", "int64_t": "long", "uint64_t": "ulong",
    "signed char": "sbyte", "unsigned char": "byte", "short": "short",
    "unsigned short": "ushort", "int": "int", "unsigned int": "uint",
    "long": "long", "unsigned long": "ulong", "long long": "long",
    "unsigned long long": "ulong", "float": "float", "double": "double",
    "intptr_t": "IntPtr", "uintptr_t": "UIntPtr",
}


def _identifier(value: str, fallback: str = "NativeClass") -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", value.strip())
    if not value:
        value = fallback
    if value[0].isdigit():
        value = "_" + value
    if value in {"class", "namespace", "event", "object", "string", "base", "this", "ref", "out"}:
        value = "@" + value
    return value


def _mask_comments_and_strings(text: str) -> str:
    """Blank comments and literals while preserving offsets and newlines."""
    chars = list(text)
    i = 0
    state = "code"
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                state = "block"
                i += 2
                continue
            if ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                state = "line"
                i += 2
                continue
            if ch == '"':
                chars[i] = " "
                state = "string"
            elif ch == "'":
                chars[i] = " "
                state = "char"
        elif state == "block":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                state = "code"
                i += 2
                continue
            if ch not in "\r\n":
                chars[i] = " "
        elif state == "line":
            if ch in "\r\n":
                state = "code"
            else:
                chars[i] = " "
        else:
            if ch == "\\" and i + 1 < len(text):
                chars[i] = chars[i + 1] = " "
                i += 2
                continue
            if ch in "\r\n":
                state = "code"
            else:
                chars[i] = " "
                if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                    state = "code"
        i += 1
    return "".join(chars)


def _balanced_end(masked: str, opening: int) -> int | None:
    depth = 0
    for pos in range(opening, len(masked)):
        if masked[pos] == "{":
            depth += 1
        elif masked[pos] == "}":
            depth -= 1
            if depth == 0:
                return pos
    return None


def _functions(source: str) -> list[dict]:
    masked = _mask_comments_and_strings(source)
    result = []
    cursor = 0
    while match := _FUNCTION_RE.search(masked, cursor):
        opening = match.end() - 1
        closing = _balanced_end(masked, opening)
        if closing is None:
            cursor = match.end()
            continue
        result.append({
            "return_type": match.group("ret").strip(),
            "native_name": match.group("name").strip(),
            "params": match.group("params").strip(),
            "body": source[opening + 1:closing],
            "start": match.start(),
            "end": closing + 1,
        })
        cursor = closing + 1
    return result


def _mapped_type(native_type: str, *, pointer_context: bool = False) -> str:
    value = re.sub(r"\b(const|volatile|restrict)\b", "", native_type).strip()
    value = re.sub(r"\s+", " ", value)
    if value.endswith("*"):
        base = value[:-1].strip().lower()
        if base in {"undefined", "undefined1", "byte", "char", "void"}:
            return "byte*" if base != "void" else "void*"
        mapped = _CS_TYPES.get(base)
        if mapped and mapped not in {"IntPtr", "UIntPtr"}:
            return mapped + "*"
        return "byte*" if pointer_context else "IntPtr"
    return _CS_TYPES.get(value.lower(), "IntPtr")


def _split_params(params: str) -> list[str]:
    if not params.strip() or params.strip() == "void":
        return []
    # IL2CPP decompiler signatures do not normally place commas inside templates;
    # preserve a basic nesting check for the few generic types that do.
    chunks, current, depth = [], [], 0
    for char in params:
        if char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            chunks.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        chunks.append("".join(current).strip())
    return chunks


def _parameter_declarations(params: str) -> tuple[str, list[str]]:
    declarations, warnings = [], []
    for index, item in enumerate(_split_params(params)):
        item = re.sub(r"\b(const|volatile|restrict)\b", "", item).strip()
        parts = item.rsplit(None, 1)
        if len(parts) == 1:
            warnings.append(f"unparsed parameter: {item}")
            declarations.append(f"IntPtr arg{index}")
            continue
        type_name, name = parts
        name = name.strip("*&")
        if name in {"method", "rgctx"} or "MethodInfo" in type_name:
            continue
        declaration_type = _mapped_type(type_name, pointer_context=True)
        if declaration_type in {"IntPtr", "UIntPtr"} and "*" in type_name:
            warnings.append(f"opaque pointer parameter: {item}")
        declarations.append(f"{declaration_type} {_identifier(name, f'arg{index}')}")
    return ", ".join(declarations), warnings


def _translate_body(body: str, return_type: str) -> tuple[str, list[str]]:
    code = body.strip("\r\n \t")
    warnings: list[str] = []

    # Normalize common C/C++ integer type spellings used by Ghidra.
    replacements = [
        (r"\bundefined16\b", "UInt128"), (r"\bundefined8\b", "ulong"),
        (r"\bundefined4\b", "uint"), (r"\bundefined2\b", "ushort"),
        (r"\bundefined1\b", "byte"), (r"\bundefined\b", "byte"),
        (r"\buint8_t\b", "byte"), (r"\bint8_t\b", "sbyte"),
        (r"\buint16_t\b", "ushort"), (r"\bint16_t\b", "short"),
        (r"\buint32_t\b", "uint"), (r"\bint32_t\b", "int"),
        (r"\buint64_t\b", "ulong"), (r"\bint64_t\b", "long"),
        (r"\bunsigned long long\b", "ulong"), (r"\blong long\b", "long"),
    ]
    for pattern, replacement in replacements:
        code = re.sub(pattern, replacement, code)

    # Rewrite Ghidra's common native object-field expression into an explicit
    # byte-address calculation. This preserves the offset operation in C# unsafe code.
    mem_pattern = re.compile(
        r"\*\s*\(\s*(?P<type>[A-Za-z_]\w*)\s*\*\s*\)\s*\(\s*"
        r"(?P<base>[A-Za-z_]\w*)\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\s*\)"
    )
    def replace_memory(match: re.Match) -> str:
        ctype = match.group("type")
        target = _mapped_type(ctype)
        base = match.group("base")
        offset = match.group("offset")
        if target in {"IntPtr", "UIntPtr", "UInt128"}:
            warnings.append(f"native field type {ctype} needs layout review")
            target = "byte"
        return f"*(({target}*)((byte*){base} + {offset}))"
    code = mem_pattern.sub(replace_memory, code)

    # Ghidra often expresses pointer loads as *(type *)(address). Rewrite
    # innermost casts first; address arithmetic on raw pointers is byte-based.
    cast_pattern = re.compile(
        r"\*\s*\(\s*(?P<type>[A-Za-z_]\w*)\s*\*\s*\)\s*"
        r"\(\s*(?P<expr>(?:[A-Za-z_]\w*|0x[0-9A-Fa-f]+|\d+|[()+\-*/\s]|\([^()]*\))+?)\s*\)"
    )
    def replace_cast(match: re.Match) -> str:
        ctype = match.group("type")
        element = _mapped_type(ctype)
        expr = match.group("expr").strip()
        if element in {"IntPtr", "UIntPtr", "UInt128"}:
            warnings.append(f"native pointer cast {ctype} needs layout review")
            element = "byte"
        if re.fullmatch(r"[A-Za-z_]\w*\s*\+\s*(?:0x[0-9A-Fa-f]+|\d+)", expr):
            base, offset = re.split(r"\s*\+\s*", expr, maxsplit=1)
            return f"*(({element}*)((byte*){base.strip()} + {offset.strip()}))"
        return f"*(({element}*)({expr}))"
    previous = None
    while previous != code:
        previous = code
        code = cast_pattern.sub(replace_cast, code)
    direct_cast_pattern = re.compile(
        r"\*\s*\(\s*(?P<type>[A-Za-z_]\w*)\s*\*\s*\)\s*(?P<expr>[A-Za-z_]\w*)"
    )
    code = direct_cast_pattern.sub(
        lambda m: f"*(({_mapped_type(m.group('type')) if _mapped_type(m.group('type')) not in {'IntPtr', 'UIntPtr'} else 'byte'}*){m.group('expr')})",
        code)
    code = re.sub(r"\bNULL\b", "IntPtr.Zero", code)
    code = re.sub(r"\bfalse\b", "false", code, flags=re.IGNORECASE)
    code = re.sub(r"\btrue\b", "true", code, flags=re.IGNORECASE)

    # Ghidra emits `undefined *name` locals. Preserve pointer semantics under unsafe C#.
    code = re.sub(r"\bbyte\s+\*\s*([A-Za-z_]\w*)", r"byte* \1", code)
    code = re.sub(r"\b(ulong|uint|ushort|byte|long|int|short)\s+\*\s*([A-Za-z_]\w*)",
                  r"\1* \2", code)
    code = re.sub(r"\b(byte|sbyte|short|ushort|int|uint|long|ulong|float|double)\s+"
                  r"([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]",
                  r"\1[] \2 = new \1[\3]", code)

    if "->" in code:
        warnings.append("pointer-member access (->) requires native struct layout")
    if re.search(r"\b(?:CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|undefined\w*)\b", code):
        warnings.append("Ghidra-specific type/operation remains")
    if re.search(r"\b(?:FUN_[0-9A-Fa-f]+|thunk_FUN_[0-9A-Fa-f]+)\s*\(", code):
        warnings.append("calls to Ghidra FUN_ targets need cross-class linkage")
    if re.search(r"\bfunc_0x[0-9A-Fa-f]+\s*\(", code):
        warnings.append("calls to native address helpers need cross-function linkage")
    if re.search(r"\b(?:PTR_)?DAT_[0-9A-Fa-f]+\b|\bbRam[0-9A-Fa-f]+\b", code):
        warnings.append("native global data address needs a recovered field mapping")
    if re.search(r"\(\s*[A-Za-z_]\w*_o\s*\*\s*\)", code):
        warnings.append("IL2CPP object cast needs a recovered struct definition")
    if return_type == "bool":
        code = re.sub(r"\breturn\s+0\s*;", "return false;", code)
        code = re.sub(r"\breturn\s+1\s*;", "return true;", code)
        def bool_return(match: re.Match) -> str:
            expression = match.group(2).strip()
            if "*((byte*)" in expression and not re.search(r"(?:==|!=|<=|>=|&&|\|\|)", expression):
                expression += " != 0"
            return match.group(1) + expression + ";"
        code = re.sub(r"(?m)^(\s*return\s+)(.*?);\s*$", bool_return, code)
    return code, sorted(set(warnings))


def _method_name_for(function: dict, method_by_rva: dict[str, tuple[str, str]]) -> tuple[str, str | None]:
    suffix = re.search(r"_([0-9a-fA-F]{5,})$", function["native_name"])
    if suffix:
        rva_key = suffix.group(1).lower().lstrip("0") or "0"
        if rva_key in method_by_rva:
            name, signature = method_by_rva[rva_key]
            return _identifier(name, "NativeMethod"), signature
    return _identifier(function["native_name"], "NativeMethod"), None


def render_csharp_reference(source: str, source_name: str = "NativeClass.c") -> tuple[str, dict]:
    """Translate functions with bodies; emit explicit stubs for missing bodies."""
    class_match = _CLASS_RE.search(source)
    class_name = _identifier(class_match.group(1) if class_match else Path(source_name).stem,
                             "NativeClass")
    metadata = {}
    for match in _METHOD_RE.finditer(source):
        method_name, rva, signature = (part.strip() for part in match.groups())
        metadata[rva[2:].lower().lstrip("0") or "0"] = (method_name, signature.strip())

    functions = _functions(source)
    functions_by_rva: dict[str, dict] = {}
    for function in functions:
        suffix = re.search(r"_([0-9a-fA-F]{5,})$", function["native_name"])
        if suffix:
            functions_by_rva[suffix.group(1).lower().lstrip("0") or "0"] = function

    lines = [
        "// Generated by DucAPK's offline C-to-C# pseudocode translator.",
        "// Unsafe methods preserve recognizable native operations; review every warning before use.",
        "// Original .c inputs are not modified or copied to this output.",
        "using System;",
        "namespace DucAPK.Generated",
        "{",
        f"    public static unsafe class {class_name}",
        "    {",
    ]
    translated = 0
    stubbed = 0
    warnings: list[dict] = []
    used_names: set[str] = set()

    for rva_key, (method_label, signature) in metadata.items():
        if rva_key == "0":
            continue
        function = functions_by_rva.get(rva_key)
        method_name = _identifier(method_label, "NativeMethod")
        rva = "0x" + rva_key
        if method_name in used_names:
            method_name = f"{method_name}_RVA_{rva_key}"
        used_names.add(method_name)
        lines.append(f"        // {method_label} | native RVA {rva}")
        lines.append("        // Metadata signature: " + signature.replace("*/", "* /").replace("\n", " "))
        if function is None:
            return_match = re.search(r"^\s*([\w.$<>]+)", signature)
            return_type = _mapped_type(return_match.group(1)) if return_match else "void"
            if return_type in {"IntPtr", "UIntPtr", "UInt128"}:
                return_type = "IntPtr" if return_type != "UInt128" else "UInt128"
            lines.extend([
                f"        public static {return_type} {method_name}_RVA_{rva_key}()",
                "        {",
                "            throw new NotImplementedException(\"No Ghidra body was exported for this RVA.\");",
                "        }",
                "",
            ])
            stubbed += 1
            continue

        return_type = _mapped_type(function["return_type"])
        managed_return = re.match(r"\s*([\w.<>]+)\s+", signature)
        if managed_return and _mapped_type(managed_return.group(1)) == "bool":
            return_type = "bool"
        if return_type in {"IntPtr", "UIntPtr"} and "*" not in function["return_type"]:
            warnings.append({"method": method_name, "rva": rva, "warning": "unknown native return type mapped to IntPtr"})
        params, parameter_warnings = _parameter_declarations(function["params"])
        body, body_warnings = _translate_body(function["body"], return_type)
        all_warnings = parameter_warnings + body_warnings
        for warning in all_warnings:
            warnings.append({"method": method_name, "rva": rva, "warning": warning})
        if all_warnings:
            lines.append("        // REVIEW: " + "; ".join(sorted(set(all_warnings))))
        lines.extend([
            f"        public static {return_type} {method_name}_RVA_{rva_key}({params})",
            "        {",
            *["            " + line if line else "" for line in body.splitlines()],
            "        }",
            "",
        ])
        translated += 1

    # Include any decompiled bodies that did not correlate with method metadata.
    metadata_rvas = set(metadata)
    for function in functions:
        suffix = re.search(r"_([0-9a-fA-F]{5,})$", function["native_name"])
        key = suffix.group(1).lower().lstrip("0") if suffix else ""
        if key and key in metadata_rvas:
            continue
        name = _identifier(function["native_name"], "NativeMethod")
        ret = _mapped_type(function["return_type"])
        params, _ = _parameter_declarations(function["params"])
        body, body_warnings = _translate_body(function["body"], ret)
        if name in used_names:
            name += "_Native"
        used_names.add(name)
        lines.append(f"        // Native function not matched to managed metadata: {function['native_name']}")
        if body_warnings:
            lines.append("        // REVIEW: " + "; ".join(body_warnings))
        lines.extend([f"        public static {ret} {name}({params})", "        {"])
        lines.extend(["            " + line if line else "" for line in body.splitlines()])
        lines.extend(["        }", ""])
        translated += 1
        warnings.extend({"method": name, "warning": warning} for warning in body_warnings)

    lines.extend(["    }", "}", ""])
    return "\n".join(lines), {"methods_translated": translated, "methods_stubbed": stubbed,
                               "warnings": warnings, "class_name": class_name}


def export_c_tree(source_root: Path, output_root: Path,
                  emit=lambda _message: None) -> dict:
    """Translate every .c file recursively, retaining the original tree untouched."""
    source_root = source_root.resolve()
    output_root = output_root.resolve()
    if not source_root.is_dir():
        raise ValueError(f"Không tìm thấy thư mục C: {source_root}")
    files = sorted(path for path in source_root.rglob("*.c") if path.is_file())
    if not files:
        raise ValueError(f"Không tìm thấy file .c trong: {source_root}")

    output_root.mkdir(parents=True, exist_ok=True)
    written = translated = stubbed = failed = 0
    used_targets: set[Path] = set()
    file_report = []
    for index, source_path in enumerate(files, 1):
        try:
            source = source_path.read_text(encoding="utf-8", errors="replace")
            rendered, stats = render_csharp_reference(source, source_path.name)
            relative = source_path.relative_to(source_root)
            class_name = stats["class_name"]
            target = output_root / relative.parent / f"{class_name}.cs"
            if target in used_targets:
                digest = hashlib.sha1(str(relative).encode("utf-8")).hexdigest()[:8]
                target = target.with_name(f"{class_name}_{digest}.cs")
            used_targets.add(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered, encoding="utf-8", newline="\n")
            written += 1
            translated += stats["methods_translated"]
            stubbed += stats["methods_stubbed"]
            file_report.append({"source": str(relative), "output": str(target.relative_to(output_root)),
                                **stats})
            emit(f"Dịch C# {index}/{len(files)}: {source_path.name}; "
                 f"logic chuyển được {stats['methods_translated']}, stub {stats['methods_stubbed']}, "
                 f"cần rà soát {len(stats['warnings'])}")
        except OSError as error:
            failed += 1
            emit(f"LỖI dịch {source_path}: {error}")
    report = {"format": "ducapk-csharp-translation-v1",
              "translation": "offline-best-effort-native-pseudocode",
              "warning": "Generated unsafe C# preserves recognized pseudocode only. Native object layouts, helper calls, and ABI assumptions must be reviewed; missing bodies remain stubs.",
              "files_found": len(files), "files_written": written,
              "methods_translated": translated, "methods_stubbed": stubbed,
              "files_failed": failed, "files": file_report}
    (output_root / "translation_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
