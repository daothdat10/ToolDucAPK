"""Sync and locally search selected upstream Ghidra source modules."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from typing import Callable
import tkinter as tk
from tkinter import ttk


UPSTREAM_URL = "https://github.com/NationalSecurityAgency/ghidra.git"
SOURCE_DIRS = (
    "Ghidra/Features/Decompiler",
    "Ghidra/Features/Base",
    "Ghidra/Framework/SoftwareModeling",
    "Ghidra/Framework/Generic",
    "Ghidra/Processors/ARM",
)
TEXT_SUFFIXES = {
    ".java", ".md", ".txt", ".xml", ".properties", ".json", ".py", ".c",
    ".h", ".cc", ".cpp", ".hpp", ".gradle", ".gradle.kts", ".cs", ".html",
}
MAX_FILE_BYTES = 1024 * 1024
MAX_INDEX_BYTES = 500 * 1024 * 1024


def _git(args: list[str], cwd: Path | None, emit: Callable[[str], None]) -> str:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    process = subprocess.Popen(
        ["git", *args], cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    output: list[str] = []
    assert process.stdout is not None
    for line in process.stdout:
        line = line.rstrip()
        if line:
            output.append(line)
            emit(line)
    code = process.wait()
    if code:
        details = "\n".join(output[-12:]) or f"git thoát với mã {code}"
        raise RuntimeError(details)
    return "\n".join(output)


def _is_indexable(path: Path) -> bool:
    rel_parts = {part.casefold() for part in path.parts}
    if ".git" in rel_parts or "node_modules" in rel_parts:
        return False
    if any(part in {"test", "tests", "testdata", "testfixtures"} for part in rel_parts):
        return False
    return path.suffix.casefold() in TEXT_SUFFIXES or path.name.casefold() in {
        "readme", "license", "build.gradle", "settings.gradle",
    }


def _create_index(repo: Path, db_path: Path,
                  emit: Callable[[str], None] = lambda _: None) -> dict:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = db_path.with_name(db_path.name + ".tmp")
    temp_path.unlink(missing_ok=True)
    connection = sqlite3.connect(temp_path)
    indexed_files = 0
    indexed_bytes = 0
    try:
        connection.execute("CREATE VIRTUAL TABLE source USING fts5(path UNINDEXED, content)")
        connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        rows = []
        for source_dir in SOURCE_DIRS:
            base = repo / Path(source_dir)
            if not base.is_dir():
                emit(f"Bỏ qua thư mục không có trong checkout: {source_dir}")
                continue
            for path in sorted(base.rglob("*")):
                if not path.is_file() or not _is_indexable(path):
                    continue
                try:
                    size = path.stat().st_size
                    if size > MAX_FILE_BYTES or indexed_bytes + size > MAX_INDEX_BYTES:
                        continue
                    raw = path.read_bytes()
                    text = raw.decode("utf-8", errors="replace")
                except OSError:
                    continue
                if not text.strip() or "\x00" in text[:4096]:
                    continue
                rows.append((path.relative_to(repo).as_posix(), text))
                indexed_files += 1
                indexed_bytes += len(raw)
                if len(rows) >= 250:
                    connection.executemany("INSERT INTO source(path, content) VALUES (?, ?)", rows)
                    connection.commit()
                    rows.clear()
                    emit(f"Đã lập chỉ mục {indexed_files:,} file Ghidra...")
        if rows:
            connection.executemany("INSERT INTO source(path, content) VALUES (?, ?)", rows)
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=repo, text=True,
            encoding="ascii", errors="replace",
        ).strip()
        updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        metadata = {
            "commit": commit,
            "updated_at": updated_at,
            "indexed_files": str(indexed_files),
            "indexed_bytes": str(indexed_bytes),
            "source_url": UPSTREAM_URL,
            "source_dirs": json.dumps(SOURCE_DIRS),
        }
        connection.executemany("INSERT INTO metadata(key, value) VALUES (?, ?)", metadata.items())
        connection.commit()
    except Exception:
        connection.close()
        temp_path.unlink(missing_ok=True)
        raise
    else:
        connection.close()
    os.replace(temp_path, db_path)
    emit(f"Đã lập chỉ mục {indexed_files:,} file, {indexed_bytes / (1024 * 1024):.1f} MiB.")
    return {"commit": commit, "updated_at": updated_at,
            "indexed_files": indexed_files, "indexed_bytes": indexed_bytes}


def update_ghidra_knowledge(root: Path, emit: Callable[[str], None] = lambda _: None) -> dict:
    """Shallow sparse-sync upstream source and atomically rebuild its FTS index."""
    knowledge_dir = root / "knowledge"
    repo = knowledge_dir / "ghidra_upstream"
    index_db = knowledge_dir / "ghidra_source_index.sqlite3"
    knowledge_dir.mkdir(parents=True, exist_ok=True)
    if (repo / ".git").is_dir():
        origin = subprocess.check_output(
            ["git", "remote", "get-url", "origin"], cwd=repo, text=True,
            encoding="utf-8", errors="replace",
        ).strip().rstrip("/")
        if origin.removesuffix(".git").casefold() != UPSTREAM_URL.removesuffix(".git").casefold():
            raise RuntimeError(f"Nguồn Git tại {repo} không phải repo Ghidra chính thức: {origin}")
        emit("Đang cập nhật checkout Ghidra từ GitHub...")
        _git(["pull", "--ff-only", "--progress"], repo, emit)
    elif repo.exists():
        raise RuntimeError(f"Đường dẫn nguồn đã tồn tại nhưng không phải checkout Git: {repo}")
    else:
        emit("Đang tải checkout nông, chỉ lấy các module Ghidra cần lập chỉ mục...")
        _git(["clone", "--depth", "1", "--filter=blob:none", "--sparse", "--progress",
              UPSTREAM_URL, str(repo)], knowledge_dir, emit)
    emit("Đang chọn module decompiler, loader, framework và ARM...")
    _git(["sparse-checkout", "set", *SOURCE_DIRS], repo, emit)
    commit = subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"], cwd=repo, text=True,
        encoding="ascii", errors="replace",
    ).strip()
    emit(f"Checkout Ghidra tại commit {commit}; bắt đầu lập chỉ mục tra cứu.")
    result = _create_index(repo, index_db, emit)
    result["index_path"] = str(index_db)
    result["repo_path"] = str(repo)
    return result


def read_index_info(db_path: Path) -> dict | None:
    if not db_path.is_file():
        return None
    connection = None
    try:
        connection = sqlite3.connect(db_path)
        return dict(connection.execute("SELECT key, value FROM metadata"))
    except sqlite3.Error:
        return None
    finally:
        if connection is not None:
            connection.close()


def search_ghidra_source(db_path: Path, query: str, limit: int = 60) -> list[dict]:
    terms = re.findall(r"[\w.$-]+", query, flags=re.UNICODE)
    if not terms or not db_path.is_file():
        return []
    expression = " AND ".join('"' + term.replace('"', '""') + '"' for term in terms[:12])
    connection = sqlite3.connect(db_path)
    try:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT path, content, snippet(source, 1, '⟦', '⟧', ' … ', 18) AS excerpt "
            "FROM source WHERE source MATCH ? ORDER BY rank LIMIT ?",
            (expression, max(1, min(limit, 200))),
        ).fetchall()
    finally:
        connection.close()
    result = []
    for row in rows:
        content = row["content"]
        lower = content.casefold()
        location = min((lower.find(term.casefold()) for term in terms if lower.find(term.casefold()) >= 0), default=0)
        line = content.count("\n", 0, location) + 1
        result.append({"path": row["path"], "line": line, "excerpt": row["excerpt"]})
    return result


class GhidraSourceView(ttk.Frame):
    """Small UI to update and query the locally indexed Ghidra source."""

    def __init__(self, parent, root: Path, colors: dict):
        super().__init__(parent, padding=12)
        self.tk_module = tk
        self.ttk = ttk
        self.root_path = root
        self.colors = colors
        self.index_db = root / "knowledge" / "ghidra_source_index.sqlite3"
        self.busy = False
        self.results: list[dict] = []
        self.query = tk.StringVar()
        self.status = tk.StringVar()
        self._build()
        self._refresh_status()

    def _build(self):
        tk, ttk = self.tk_module, self.ttk
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="GHIDRA UPSTREAM SOURCE", foreground=self.colors["blue"],
                  font=("Segoe UI Semibold", 10)).pack(side="left")
        self.update_button = ttk.Button(top, text="Cập nhật kiến thức", command=self._start_update)
        self.update_button.pack(side="right")
        ttk.Label(self, text="Đồng bộ source chính thức, rồi lập chỉ mục để tra cứu trong DucAPK. "
                             "Luồng phân tích APK đã gọi Ghidra trực tiếp; chỉ mục này giúp tra cứu cách Ghidra hoạt động, "
                             "không tự thay đổi bộ phân tích hay giải mã metadata tùy biến.",
                  wraplength=980, foreground=self.colors["muted"]).pack(anchor="w", pady=(0, 8))
        ttk.Label(self, textvariable=self.status, wraplength=980).pack(anchor="w", pady=(0, 8))
        self.progress = ttk.Progressbar(self, mode="indeterminate", length=260)
        self.progress.pack(fill="x", pady=(0, 8))
        search_row = ttk.Frame(self)
        search_row.pack(fill="x", pady=(0, 8))
        ttk.Label(search_row, text="Tra cứu source").pack(side="left", padx=(0, 8))
        entry = ttk.Entry(search_row, textvariable=self.query)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _: self._search())
        ttk.Button(search_row, text="Tìm", command=self._search).pack(side="left", padx=(8, 0))
        body = ttk.PanedWindow(self, orient="horizontal")
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body, width=430)
        right = ttk.Frame(body)
        body.add(left, weight=2)
        body.add(right, weight=3)
        tree_box = ttk.Frame(left)
        tree_box.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_box, columns=("file", "line"), show="headings", height=12)
        self.tree.heading("file", text="FILE GIDRA")
        self.tree.heading("line", text="DÒNG")
        self.tree.column("file", width=340, anchor="w")
        self.tree.column("line", width=60, anchor="e")
        scroll = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._selected)
        ttk.Label(right, text="ĐOẠN SOURCE", foreground=self.colors["blue"],
                  font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(0, 5))
        self.detail = tk.Text(right, wrap="word", state="disabled", height=12,
                              bg=self.colors["panel"], fg=self.colors["text"],
                              insertbackground=self.colors["text"], relief="flat", padx=10, pady=8)
        detail_scroll = ttk.Scrollbar(right, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set)
        detail_scroll.pack(side="right", fill="y")
        self.detail.pack(side="left", fill="both", expand=True)
        self.log = tk.Text(self, height=6, wrap="word", state="disabled",
                           bg=self.colors["background"], fg=self.colors["muted"],
                           insertbackground=self.colors["text"], relief="flat", padx=8, pady=6)
        self.log.pack(fill="x", pady=(8, 0))

    def _append_log(self, message: str):
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _refresh_status(self):
        from ducapk.ghidra_knowledge import read_index_info

        info = read_index_info(self.index_db)
        if not info:
            self.status.set("Chưa có source Ghidra được lập chỉ mục. Bấm Cập nhật kiến thức để tải từ GitHub.")
            return
        self.status.set(f"Đã lập chỉ mục {int(info.get('indexed_files', 0)):,} file • "
                        f"commit {info.get('commit', '?')} • cập nhật {info.get('updated_at', '?')} UTC")

    def _start_update(self):
        from ducapk.ghidra_knowledge import update_ghidra_knowledge

        if self.busy:
            return
        self.busy = True
        self.update_button.configure(state="disabled")
        self.progress.start(12)
        self.status.set("Đang đồng bộ source Ghidra và lập chỉ mục...")
        self._append_log("Bắt đầu cập nhật từ NationalSecurityAgency/ghidra.")

        def emit(message: str):
            try:
                self.after(0, lambda m=message: self._append_log(m))
            except self.tk_module.TclError:
                pass

        def worker():
            try:
                result = update_ghidra_knowledge(self.root_path, emit)
                self.after(0, lambda r=result: self._update_done(r))
            except Exception as error:
                self.after(0, lambda e=str(error): self._update_error(e))

        import threading
        threading.Thread(target=worker, name="ghidra-source-update", daemon=True).start()

    def _update_done(self, result: dict):
        self.busy = False
        self.progress.stop()
        self.update_button.configure(state="normal")
        self._refresh_status()
        self._append_log(f"Hoàn tất cập nhật commit {result['commit']}; "
                         f"{result['indexed_files']:,} file đã sẵn sàng tra cứu.")

    def _update_error(self, error: str):
        self.busy = False
        self.progress.stop()
        self.update_button.configure(state="normal")
        self.status.set("Cập nhật chưa xong; xem nhật ký bên dưới để biết nguyên nhân.")
        self._append_log("LỖI: " + error)

    def _search(self):
        from ducapk.ghidra_knowledge import search_ghidra_source

        query = self.query.get().strip()
        if not query:
            return
        try:
            self.results = search_ghidra_source(self.index_db, query)
        except sqlite3.Error as error:
            self.results = []
            self._append_log("Không tra cứu được chỉ mục: " + str(error))
            return
        self.tree.delete(*self.tree.get_children())
        for index, result in enumerate(self.results):
            self.tree.insert("", "end", iid=str(index), values=(result["path"], result["line"]))
        self._append_log(f"Tra cứu “{query}”: tìm thấy {len(self.results)} kết quả.")
        if self.results:
            self.tree.selection_set("0")
            self.tree.focus("0")
            self._selected()
        else:
            self._set_detail("Không có kết quả. Nếu source chưa cập nhật, bấm Cập nhật kiến thức trước.")

    def _set_detail(self, text: str):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _selected(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        result = self.results[int(selection[0])]
        self._set_detail(f"{result['path']}:{result['line']}\n\n{result['excerpt']}")
