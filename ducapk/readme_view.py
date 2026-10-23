"""Read-only Markdown viewer for README.md inside DucAPK."""
from __future__ import annotations

from pathlib import Path
import re
import tkinter as tk
from tkinter import ttk
import webbrowser


_INLINE_RE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))")


class ReadmeView(ttk.Frame):
    def __init__(self, parent, readme_path: Path, colors: dict):
        super().__init__(parent, padding=12)
        self.readme_path, self.colors = readme_path, colors
        self.headings: list[tuple[str, str]] = []
        self.links: dict[str, str] = {}
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 10))
        ttk.Label(top, text=str(readme_path), foreground=colors["muted"],
                  font=("Consolas", 9)).pack(side="left")
        ttk.Button(top, text="Tải lại", command=self.reload).pack(side="right")
        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Frame(panes, width=230)
        right = ttk.Frame(panes)
        panes.add(left, weight=1)
        panes.add(right, weight=5)
        ttk.Label(left, text="MỤC LỤC", foreground=colors["blue"],
                  font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(0, 4))
        self.toc = ttk.Treeview(left, show="tree", selectmode="browse")
        self.toc.pack(fill="both", expand=True)
        self.toc.bind("<<TreeviewSelect>>", self._jump)

        self.text = tk.Text(right, wrap="word", bg=colors["panel"], fg=colors["text"],
                            insertbackground=colors["text"], relief="flat", borderwidth=0,
                            padx=22, pady=16, font=("Segoe UI", 10), spacing1=2, spacing3=4,
                            cursor="arrow")
        scroll = ttk.Scrollbar(right, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True, padx=(10, 0))
        accent = colors["blue"]
        self.text.tag_configure("h1", font=("Segoe UI", 18, "bold"), spacing1=6, spacing3=10)
        self.text.tag_configure("h2", font=("Segoe UI", 14, "bold"), foreground=accent,
                                spacing1=16, spacing3=6)
        self.text.tag_configure("h3", font=("Segoe UI Semibold", 11), spacing1=10, spacing3=4)
        self.text.tag_configure("bold", font=("Segoe UI Semibold", 10))
        self.text.tag_configure("code", font=("Consolas", 9), background=colors["surface"],
                                foreground=colors.get("accent", accent))
        self.text.tag_configure("block", font=("Consolas", 9), background=colors["background"],
                                lmargin1=16, lmargin2=16)
        self.text.tag_configure("bullet", lmargin1=14, lmargin2=30)
        self.text.tag_configure("link", foreground=accent, underline=True)
        self.text.tag_bind("link", "<Enter>", lambda _: self.text.configure(cursor="hand2"))
        self.text.tag_bind("link", "<Leave>", lambda _: self.text.configure(cursor="arrow"))
        self.text.tag_bind("link", "<Button-1>", self._open_link)
        self.text.bind("<MouseWheel>", lambda e: self.text.yview_scroll(-int(e.delta / 120), "units"))
        self.reload()

    def reload(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.toc.delete(*self.toc.get_children())
        self.headings.clear()
        self.links.clear()
        try:
            source = self.readme_path.read_text(encoding="utf-8")
        except OSError as error:
            self.text.insert("end", f"Không đọc được README: {error}")
        else:
            self._render(source)
        self.text.configure(state="disabled")

    def _render(self, source: str):
        in_code = False
        parent = ""
        for line in source.splitlines():
            if line.strip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                self.text.insert("end", line + "\n", "block")
                continue
            heading = re.match(r"^(#{1,3})\s+(.*)$", line)
            if heading:
                level, title = len(heading.group(1)), heading.group(2).strip()
                mark = f"h{len(self.headings)}"
                self.text.mark_set(mark, "end-1c")
                self.text.mark_gravity(mark, "left")
                self.text.insert("end", title + "\n", f"h{level}")
                node = self.toc.insert(parent if level == 3 and parent else "", "end",
                                       text=title, values=(mark,))
                if level <= 2:
                    parent = node
                self.headings.append((title, mark))
                continue
            if line.strip().startswith("|"):
                if re.match(r"^\s*\|[\s:|-]+\|\s*$", line):
                    continue
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                self.text.insert("end", "  " + "   │   ".join(cells) + "\n", "bullet")
                continue
            bullet = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
            if bullet:
                indent = "    " * (len(bullet.group(1)) // 2)
                marker = "•" if bullet.group(2) in "-*" else bullet.group(2)
                self.text.insert("end", f"{indent}{marker} ", "bullet")
                self._inline(bullet.group(3), "bullet")
                self.text.insert("end", "\n", "bullet")
                continue
            self._inline(line)
            self.text.insert("end", "\n")

    def _inline(self, line: str, base: str = ""):
        for piece in _INLINE_RE.split(line):
            if not piece:
                continue
            tags = (base,) if base else ()
            if piece.startswith("**") and piece.endswith("**"):
                self.text.insert("end", piece[2:-2], tags + ("bold",))
            elif piece.startswith("`") and piece.endswith("`"):
                self.text.insert("end", piece[1:-1], tags + ("code",))
            elif piece.startswith("["):
                label, url = re.match(r"\[([^\]]+)\]\(([^)]+)\)", piece).groups()
                tag = f"link{len(self.links)}"
                self.links[tag] = url
                self.text.insert("end", label, tags + ("link", tag))
            else:
                self.text.insert("end", piece, tags)

    def _jump(self, _event=None):
        selection = self.toc.selection()
        if selection:
            mark = self.toc.item(selection[0], "values")[0]
            self.text.see("end")
            self.text.see(mark)
            self.text.yview(mark)

    def _open_link(self, event):
        for tag in self.text.tag_names(f"@{event.x},{event.y}"):
            if tag in self.links:
                webbrowser.open(self.links[tag])
                return
