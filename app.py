from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import re
import sqlite3
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from tkinterdnd2 import DND_FILES, TkinterDnD

from ducapk.runner import (AnalysisCancelled, DEFAULT_GHIDRA_THREADS, ROOT, analyze,
                           retry_failed_only, set_ghidra_threads)
from ducapk.csharp_export import export_c_tree
from ducapk.api_translation import APIConfig, export_api, is_resumable, test_connection
from ducapk.knowledge_view import KnowledgeGraphView
from ducapk.eta import ProgressEta, finish_clock, format_duration
from ducapk.readme_view import ReadmeView
from ducapk.tech_view import TechStackView
from ducapk.ghidra_knowledge import GhidraSourceView
from ducapk.level_editor import (LevelEditorError, build_level_editor, leveldata_sources,
                                 read_leveldata, root_candidates)


COLORS = {
    "background": "#0B1020", "sidebar": "#0E1428", "panel": "#141B33",
    "surface": "#1C2542", "border": "#2A3558", "text": "#E6EAF5",
    "muted": "#8D98B8", "selection": "#26314F", "ink": "#0B1020",
    "accent": "#34D399", "accent_text": "#0B1020", "blue": "#38BDF8",
    "danger": "#F87171",
}
# Mỗi khu vực một màu nhận diện; bản "hover" sáng hơn cho trạng thái active.
ACCENTS = {
    "Green": ("#34D399", "#6EE7B7"), "Sky": ("#38BDF8", "#7DD3FC"),
    "Violet": ("#A78BFA", "#C4B5FD"), "Amber": ("#FBBF24", "#FCD34D"),
    "Rose": ("#F87171", "#FCA5A5"), "Pink": ("#F472B6", "#F9A8D4"),
}
FONT, FONT_SEMI, MONO = "Segoe UI", "Segoe UI Semibold", "Consolas"
PAGES = [
    ("01", "Phân tích", "APK → class, hàm", "Green"),
    ("02", "Duyệt mã", "Class, hàm, pseudocode", "Sky"),
    ("03", "Công nghệ", "Engine, SDK, shader", "Green"),
    ("04", "API dịch mã", "C → C# qua API", "Violet"),
    ("05", "Knowledge Graph", "Tri thức về công cụ", "Amber"),
    ("06", "Level Editor", "APK + LevelData.cs → HTML", "Pink"),
    ("07", "README", "Hướng dẫn sử dụng", "Sky"),
]
PHASE_ACCENTS = {
    "SẴN SÀNG": None, "HOÀN TẤT": "Green", "HOÀN TẤT MỘT PHẦN": "Amber",
    "LỖI": "Rose", "THỬ LẠI HÀM LỖI": "Amber", "LEVEL EDITOR": "Pink",
}
C_PATTERNS = [
    ("c_number", r"\b0x[0-9A-Fa-f]+\b|\b\d+\b"),
    ("c_call", r"\b([A-Za-z_]\w*)\s*\("),
    ("c_type", r"\b(?:void|bool|char|short|int|long|float|double|byte|ushort|uint|ulong|"
               r"undefined\d*|longlong|ulonglong|code|size_t|u?int\d+_t|struct|union|enum|"
               r"const|static|unsigned|signed)\b"),
    ("c_keyword", r"\b(?:if|else|while|for|do|return|switch|case|break|continue|goto|"
                  r"default|sizeof|typedef|NULL|true|false)\b"),
    ("c_string", r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'"),
    ("c_comment", r"//[^\n]*|/\*.*?\*/"),
]


def _mix(color: str, other: str, amount: float) -> str:
    a = [int(color[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(other[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x * amount + y * (1 - amount)):02X}" for x, y in zip(a, b))


class DucAPKApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("DucAPK — Android APK Analyzer")
        self.geometry("1320x820")
        self.minsize(1050, 680)
        self.inputs: list[Path] = []
        self.events: queue.Queue[tuple] = queue.Queue()
        self.cancel = threading.Event()
        self.worker: threading.Thread | None = None
        self.csharp_worker: threading.Thread | None = None
        self.api_worker: threading.Thread | None = None
        self.api_cancel = threading.Event()
        self.api_result: Path | None = None
        self.job: Path | None = None
        self.database: sqlite3.Connection | None = None
        self.search_after = None
        self._reset_native_progress()
        self.output_var = tk.StringVar(value=str(ROOT / "output"))
        self.full_code_var = tk.BooleanVar(value=True)
        self.level_json_var = tk.BooleanVar(value=True)
        self.jadx_var = tk.BooleanVar(value=False)
        self.native_var = tk.BooleanVar(value=False)
        self.threads_var = tk.StringVar(value=str(DEFAULT_GHIDRA_THREADS))
        self.category_vars = {
            "game": tk.BooleanVar(value=True),
            "unity": tk.BooleanVar(value=False),
            "sdk": tk.BooleanVar(value=False),
        }
        self.status_var = tk.StringVar(value="Kéo APK hoặc XAPK vào cửa sổ để bắt đầu.")
        self.phase_var = tk.StringVar(value="SẴN SÀNG")
        self.count_var = tk.StringVar(value="0 gói được chọn")
        self.search_var = tk.StringVar()
        self.api_url_var = tk.StringVar(value="https://api.openai.com/v1")
        self.api_key_var = tk.StringVar(value=os.environ.get("DUCAPK_API_KEY", ""))
        self.api_model_var = tk.StringVar(value="")
        self.api_timeout_var = tk.StringVar(value="900")
        self.api_workers_var = tk.StringVar(value="4")
        self.api_skip_generated_var = tk.BooleanVar(value=True)
        self.api_source_var = tk.StringVar()
        self.api_output_var = tk.StringVar(value=str(ROOT / "output"))
        self.api_status_var = tk.StringVar(value="Nhập kết nối API và chọn file .c / .cs để bắt đầu.")
        self.le_inputs: list[Path] = []
        self.le_source_var = tk.StringVar()
        self.le_cs_var = tk.StringVar()
        self.le_root_var = tk.StringVar()
        self.le_output_var = tk.StringVar()
        self.le_status_var = tk.StringVar(
            value="Chọn APK (hoặc job đã phân tích) và file LevelData.cs để tạo levelEditor.html.")
        self.le_worker: threading.Thread | None = None
        self.le_cancel = threading.Event()
        self.le_result: Path | None = None
        self._build_ui()
        self.after(100, self._pump)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        bg, panel, surface = COLORS["background"], COLORS["panel"], COLORS["surface"]
        border, text, muted = COLORS["border"], COLORS["text"], COLORS["muted"]
        self.configure(bg=bg)
        style.configure(".", background=bg, foreground=text, font=(FONT, 10),
                        bordercolor=border, lightcolor=bg, darkcolor=bg,
                        troughcolor=bg, focuscolor=COLORS["blue"])
        style.configure("TFrame", background=bg)
        style.configure("Panel.TFrame", background=panel)
        style.configure("TLabel", background=bg, foreground=text, font=(FONT, 10))
        style.configure("Panel.TLabel", background=panel, foreground=text, font=(FONT, 10))
        style.configure("Muted.TLabel", background=panel, foreground=muted, font=(FONT, 9))
        style.configure("Field.TLabel", background=panel, foreground=muted, font=(FONT_SEMI, 8))
        style.configure("Section.TLabel", background=panel, foreground=COLORS["blue"],
                        font=(FONT_SEMI, 10))
        style.configure("TButton", background=surface, foreground=text, bordercolor=border,
                        lightcolor=surface, darkcolor=surface, focusthickness=1,
                        focuscolor=surface, padding=(14, 8), font=(FONT_SEMI, 10))
        style.map("TButton",
                  background=[("disabled", panel), ("active", COLORS["selection"])],
                  lightcolor=[("disabled", panel), ("active", COLORS["selection"])],
                  darkcolor=[("disabled", panel), ("active", COLORS["selection"])],
                  foreground=[("disabled", border)], bordercolor=[("disabled", surface)])
        style.configure("TEntry", fieldbackground=bg, foreground=text, insertcolor=text,
                        bordercolor=border, lightcolor=bg, darkcolor=bg, padding=7)
        style.configure("TCheckbutton", background=panel, foreground=text, font=(FONT, 10),
                        indicatorbackground=bg, indicatorforeground=text,
                        upperbordercolor=border, lowerbordercolor=border, padding=(0, 3))
        style.map("TCheckbutton", background=[("active", panel)], foreground=[("active", text)],
                  indicatorbackground=[("pressed", surface)])
        for name, (accent, hover) in ACCENTS.items():
            style.configure(f"{name}.TButton", background=accent, foreground=COLORS["ink"],
                            bordercolor=accent, lightcolor=accent, darkcolor=accent,
                            focuscolor=accent, padding=(18, 8))
            style.map(f"{name}.TButton",
                      background=[("disabled", surface), ("active", hover)],
                      lightcolor=[("disabled", surface), ("active", hover)],
                      darkcolor=[("disabled", surface), ("active", hover)],
                      bordercolor=[("disabled", surface), ("active", hover)],
                      foreground=[("disabled", muted)])
            tint = _mix(accent, panel, 0.14)
            style.configure(f"{name}.Outline.TButton", background=panel, foreground=accent,
                            bordercolor=_mix(accent, panel, 0.55), lightcolor=panel,
                            darkcolor=panel, focuscolor=panel)
            style.map(f"{name}.Outline.TButton",
                      background=[("disabled", panel), ("active", tint)],
                      lightcolor=[("disabled", panel), ("active", tint)],
                      darkcolor=[("disabled", panel), ("active", tint)],
                      bordercolor=[("disabled", surface), ("active", accent)],
                      foreground=[("disabled", border), ("active", hover)])
            style.configure(f"{name}.Horizontal.TProgressbar", background=accent,
                            troughcolor=bg, bordercolor=border, lightcolor=accent,
                            darkcolor=accent, thickness=8)
            style.configure(f"{name}.TCheckbutton", indicatorforeground=accent)
            style.configure(f"{name}.Section.TLabel", foreground=accent)
            style.configure(f"{name}.TEntry")
            style.map(f"{name}.TEntry", bordercolor=[("focus", accent)],
                      lightcolor=[("focus", accent)])
        style.configure("TCombobox", fieldbackground=bg, foreground=text, background=surface,
                        arrowcolor=muted, bordercolor=border, lightcolor=bg, darkcolor=bg, padding=6)
        style.map("TCombobox", fieldbackground=[("readonly", bg)], foreground=[("readonly", text)],
                  selectbackground=[("readonly", bg)], selectforeground=[("readonly", text)],
                  bordercolor=[("focus", ACCENTS["Pink"][0])])
        style.configure("TSpinbox", fieldbackground=bg, foreground=text, background=surface,
                        insertcolor=text, arrowcolor=muted, bordercolor=border, lightcolor=bg,
                        darkcolor=bg, selectbackground=COLORS["selection"], selectforeground=text,
                        padding=(8, 5), arrowsize=12)
        style.map("TSpinbox", bordercolor=[("focus", ACCENTS["Green"][0])],
                  lightcolor=[("focus", ACCENTS["Green"][0])],
                  arrowcolor=[("pressed", ACCENTS["Green"][0]), ("active", text)],
                  background=[("active", COLORS["selection"])])
        self.option_add("*TCombobox*Listbox.background", panel)
        self.option_add("*TCombobox*Listbox.foreground", text)
        self.option_add("*TCombobox*Listbox.selectBackground", COLORS["selection"])
        self.option_add("*TCombobox*Listbox.font", (MONO, 10))
        style.configure("TPanedwindow", background=bg)
        style.configure("Sash", sashthickness=10, gripcount=0, background=bg)
        style.layout("TNotebook.Tab", [])
        style.layout("TNotebook", [("Notebook.client", {"sticky": "nswe"})])
        style.configure("TNotebook", background=bg, borderwidth=0, tabmargins=0,
                        bordercolor=bg, lightcolor=bg, darkcolor=bg)
        style.configure("Treeview", background=panel, fieldbackground=panel, foreground=text,
                        rowheight=26, borderwidth=0, font=(FONT, 10))
        style.map("Treeview", background=[("selected", COLORS["selection"])],
                  foreground=[("selected", COLORS["blue"])])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar", background=surface, troughcolor=panel,
                            bordercolor=panel, lightcolor=surface, darkcolor=surface,
                            arrowcolor=muted, gripcount=0, arrowsize=12)
            style.map(f"{orient}.TScrollbar", background=[("active", COLORS["selection"])])

    def _build_ui(self):
        self._build_styles()
        self.job_var = tk.StringVar(value="Chưa mở job")
        self._phase_pills: list[tk.Label] = []
        self.class_count_var = tk.StringVar(value="0")
        self.method_count_var = tk.StringVar(value="0")

        shell = tk.Frame(self, bg=COLORS["background"])
        shell.pack(fill="both", expand=True)
        self._build_sidebar(shell)
        content = tk.Frame(shell, bg=COLORS["background"])
        content.pack(side="left", fill="both", expand=True)

        tabs = ttk.Notebook(content)
        tabs.pack(fill="both", expand=True, padx=20, pady=(16, 10))
        self.tabs = tabs
        analysis = ttk.Frame(tabs)
        browser = ttk.Frame(tabs)
        tech_tab = ttk.Frame(tabs)
        api_tab = ttk.Frame(tabs)
        knowledge = ttk.Frame(tabs)
        level_tab = ttk.Frame(tabs)
        readme_tab = ttk.Frame(tabs)
        for page in (analysis, browser, tech_tab, api_tab, knowledge, level_tab, readme_tab):
            tabs.add(page)
        self.api_tab = api_tab
        self.tech_tab = tech_tab
        tabs.bind("<<NotebookTabChanged>>", lambda _: (self._highlight_nav(), self._refresh_tech()))

        self._build_status_bar(content)
        self._build_analysis_ui(analysis)
        self._build_browser_ui(browser)
        self._build_level_editor_ui(level_tab)

        self._page_header(tech_tab, 2, "Công nghệ game sử dụng",
                          "Engine, thư viện C#, SDK quảng cáo/analytics và shader nhận diện từ APK; "
                          "chọn một mục để xem bằng chứng và class game dùng nó.")
        self.tech_view = TechStackView(tech_tab, COLORS, ACCENTS["Green"][0],
                                       lambda: self.job, self._set_tech_job)
        self.tech_view.pack(fill="both", expand=True)

        self._page_header(api_tab, 3, "Dịch và hoàn thiện mã C# bằng API",
                          "Kết nối endpoint tương thích OpenAI, chọn nguồn .c / .cs rồi chạy dịch theo lô.")
        api_canvas = tk.Canvas(api_tab, bg=COLORS["background"], highlightthickness=0)
        api_scroll = ttk.Scrollbar(api_tab, orient="vertical", command=api_canvas.yview)
        api_canvas.configure(yscrollcommand=api_scroll.set)
        api_scroll.pack(side="right", fill="y")
        api_canvas.pack(side="left", fill="both", expand=True)
        api_body = ttk.Frame(api_canvas)
        api_window = api_canvas.create_window((0, 0), window=api_body, anchor="nw")
        api_body.bind("<Configure>", lambda _: api_canvas.configure(scrollregion=api_canvas.bbox("all")))
        api_canvas.bind("<Configure>", lambda e: api_canvas.itemconfigure(api_window, width=e.width - 4))
        self._build_api_ui(api_body)
        def bind_scroll(widget):
            if not isinstance(widget, (tk.Text, ttk.Entry)):
                widget.bind("<MouseWheel>", lambda e: api_canvas.yview_scroll(-int(e.delta / 120), "units"))
            for child in widget.winfo_children():
                bind_scroll(child)
        bind_scroll(api_body)

        self._page_header(knowledge, 4, "Kho tri thức và mã nguồn",
                          "Bản đồ chức năng của DucAPK và kho mã nguồn tham khảo để tra cứu.")
        knowledge_nav = ttk.Frame(knowledge)
        knowledge_nav.pack(fill="x", padx=12, pady=(0, 8))
        self.knowledge_graph_button = ttk.Button(
            knowledge_nav, text="DucAPK", style="Amber.TButton",
            command=lambda: self._show_knowledge_page(False))
        self.knowledge_graph_button.pack(side="left", padx=(0, 6))
        self.ghidra_source_button = ttk.Button(
            knowledge_nav, text="Mã nguồn tham khảo", style="Amber.Outline.TButton",
            command=lambda: self._show_knowledge_page(True))
        self.ghidra_source_button.pack(side="left")
        knowledge_host = ttk.Frame(knowledge)
        knowledge_host.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        knowledge_host.rowconfigure(0, weight=1)
        knowledge_host.columnconfigure(0, weight=1)
        graph_tab = ttk.Frame(knowledge_host)
        ghidra_source_tab = ttk.Frame(knowledge_host)
        graph_tab.grid(row=0, column=0, sticky="nsew")
        ghidra_source_tab.grid(row=0, column=0, sticky="nsew")
        self.knowledge_view = KnowledgeGraphView(
            graph_tab, ROOT / "knowledge" / "ducapk_knowledge_graph.json",
            {**COLORS, "blue": ACCENTS["Amber"][0]})
        self.knowledge_view.pack(fill="both", expand=True)
        self.ghidra_source_view = GhidraSourceView(
            ghidra_source_tab, ROOT, {**COLORS, "blue": ACCENTS["Amber"][0]})
        self.ghidra_source_view.pack(fill="both", expand=True)
        graph_tab.tkraise()

        self._page_header(readme_tab, 6, "Hướng dẫn sử dụng DucAPK",
                          "Nội dung README.md của tool; chọn mục ở bên trái để nhảy tới phần cần đọc.")
        ReadmeView(readme_tab, ROOT / "README.md",
                   {**COLORS, "blue": ACCENTS["Sky"][0]}).pack(fill="both", expand=True)

        self.phase_var.trace_add("write", lambda *_: self._paint_phase())
        self._paint_phase()
        self._highlight_nav()

    def _refresh_tech(self):
        if self.tabs.select() == str(self.tech_tab):
            self.tech_view.refresh()

    def _set_tech_job(self, job: Path):
        if (job / "methods.sqlite").is_file():
            self._load_job(job)
        else:
            self.job = job.resolve()

    def _show_knowledge_page(self, show_ghidra_source: bool):
        if show_ghidra_source:
            self.ghidra_source_view.master.tkraise()
            self.ghidra_source_button.configure(style="Amber.TButton")
            self.knowledge_graph_button.configure(style="Amber.Outline.TButton")
        else:
            self.knowledge_view.master.tkraise()
            self.knowledge_graph_button.configure(style="Amber.TButton")
            self.ghidra_source_button.configure(style="Amber.Outline.TButton")

    # ---------- khung chung ----------
    def _build_sidebar(self, parent):
        side_bg = COLORS["sidebar"]
        sidebar = tk.Frame(parent, bg=side_bg, width=232)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Frame(parent, bg=COLORS["border"], width=1).pack(side="left", fill="y")

        brand = tk.Frame(sidebar, bg=side_bg)
        brand.pack(fill="x", padx=18, pady=(20, 22))
        tk.Label(brand, text="D", bg=COLORS["accent"], fg=COLORS["ink"], width=2,
                 font=(FONT, 15, "bold")).pack(side="left", ipady=2)
        names = tk.Frame(brand, bg=side_bg)
        names.pack(side="left", padx=(10, 0))
        tk.Label(names, text="DucAPK", bg=side_bg, fg=COLORS["text"],
                 font=(FONT, 14, "bold")).pack(anchor="w")
        tk.Label(names, text="Android APK Analyzer", bg=side_bg, fg=COLORS["muted"],
                 font=(FONT, 8)).pack(anchor="w")

        tk.Label(sidebar, text="QUY TRÌNH", bg=side_bg, fg=COLORS["muted"],
                 font=(FONT_SEMI, 8)).pack(anchor="w", padx=20, pady=(0, 6))
        self._nav_items = []
        for index, (number, title, subtitle, accent) in enumerate(PAGES):
            item = tk.Frame(sidebar, bg=side_bg, cursor="hand2")
            item.pack(fill="x", padx=10, pady=2)
            bar = tk.Frame(item, bg=side_bg, width=3)
            bar.pack(side="left", fill="y")
            badge = tk.Label(item, text=number, bg=side_bg, fg=COLORS["muted"], width=3,
                             font=(MONO, 10, "bold"))
            badge.pack(side="left", padx=(8, 4), pady=9)
            texts = tk.Frame(item, bg=side_bg)
            texts.pack(side="left", fill="x", pady=7)
            title_label = tk.Label(texts, text=title, bg=side_bg, fg=COLORS["text"],
                                   font=(FONT_SEMI, 10), anchor="w")
            title_label.pack(anchor="w")
            sub_label = tk.Label(texts, text=subtitle, bg=side_bg, fg=COLORS["muted"],
                                 font=(FONT, 8), anchor="w")
            sub_label.pack(anchor="w")
            parts = (item, badge, texts, title_label, sub_label)
            self._nav_items.append((parts, bar, badge, title_label, accent))
            for widget in parts:
                widget.bind("<Button-1>", lambda _, i=index: self.tabs.select(i))
                widget.bind("<Enter>", lambda _, i=index: self._highlight_nav(hover=i))
                widget.bind("<Leave>", lambda _: self._highlight_nav())

        legend = tk.Frame(sidebar, bg=side_bg)
        legend.pack(side="bottom", fill="x", padx=20, pady=18)
        tk.Label(legend, text="TRẠNG THÁI", bg=side_bg, fg=COLORS["muted"],
                 font=(FONT_SEMI, 8)).pack(anchor="w", pady=(0, 6))
        for accent, label in (("Green", "Hoàn tất"), ("Sky", "Đang chạy"),
                              ("Amber", "Một phần / thử lại"), ("Rose", "Lỗi")):
            row = tk.Frame(legend, bg=side_bg)
            row.pack(anchor="w", pady=1)
            tk.Frame(row, bg=ACCENTS[accent][0], width=8, height=8).pack(side="left", padx=(0, 8))
            tk.Label(row, text=label, bg=side_bg, fg=COLORS["muted"], font=(FONT, 8)).pack(side="left")
        tk.Label(legend, text="LOCAL  ·  WINDOWS", bg=side_bg, fg=COLORS["border"],
                 font=(FONT_SEMI, 8)).pack(anchor="w", pady=(12, 0))

    def _highlight_nav(self, hover: int | None = None):
        try:
            current = self.tabs.index(self.tabs.select())
        except tk.TclError:
            current = 0
        for index, (parts, bar, badge, title_label, accent) in enumerate(self._nav_items):
            color = ACCENTS[accent][0]
            active = index == current
            bg = (_mix(color, COLORS["sidebar"], 0.12) if active
                  else COLORS["surface"] if index == hover else COLORS["sidebar"])
            for widget in parts:
                widget.configure(bg=bg)
            bar.configure(bg=color if active else bg)
            badge.configure(fg=color if active or index == hover else COLORS["muted"])
            title_label.configure(fg=color if active else COLORS["text"])

    def _build_status_bar(self, parent):
        bar = tk.Frame(parent, bg=COLORS["sidebar"], height=30)
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)
        tk.Frame(parent, bg=COLORS["border"], height=1).pack(side="bottom", fill="x")
        self._phase_pills.append(self._make_pill(bar, COLORS["sidebar"]))
        self._phase_pills[-1].pack(side="left", padx=(14, 10), pady=5)
        tk.Label(bar, textvariable=self.job_var, bg=COLORS["sidebar"], fg=COLORS["muted"],
                 font=(MONO, 9)).pack(side="right", padx=14)
        tk.Label(bar, text="JOB", bg=COLORS["sidebar"], fg=COLORS["border"],
                 font=(FONT_SEMI, 8)).pack(side="right")
        tk.Label(bar, textvariable=self.status_var, bg=COLORS["sidebar"], fg=COLORS["text"],
                 font=(FONT, 9), anchor="w", width=1).pack(side="left", fill="x", expand=True)

    def _make_pill(self, parent, bg):
        return tk.Label(parent, textvariable=self.phase_var, bg=bg, fg=COLORS["muted"],
                        font=(FONT_SEMI, 8), padx=10, pady=1)

    def _paint_phase(self):
        phase = self.phase_var.get()
        accent = PHASE_ACCENTS.get(phase, "Sky")
        color = ACCENTS[accent][0] if accent else COLORS["muted"]
        for pill in self._phase_pills:
            pill.configure(fg=color, bg=_mix(color, COLORS["panel"], 0.16))

    def _page_header(self, parent, page: int, title: str, description: str):
        number, name, _, accent = PAGES[page]
        color = ACCENTS[accent][0]
        header = ttk.Frame(parent)
        header.pack(fill="x", pady=(0, 14))
        ttk.Label(header, text=f"BƯỚC {number}  ·  {name.upper()}", foreground=color,
                  font=(FONT_SEMI, 9)).pack(anchor="w")
        ttk.Label(header, text=title, font=(FONT, 17, "bold")).pack(anchor="w", pady=(2, 0))
        ttk.Label(header, text=description, foreground=COLORS["muted"],
                  font=(FONT, 10)).pack(anchor="w")
        return header

    def _card(self, parent, step: str, title: str, accent: str, hint: str = ""):
        color = ACCENTS[accent][0]
        outer = tk.Frame(parent, bg=COLORS["panel"], highlightthickness=1,
                         highlightbackground=COLORS["border"], highlightcolor=COLORS["border"])
        tk.Frame(outer, bg=color, height=3).pack(fill="x")
        head = ttk.Frame(outer, style="Panel.TFrame", padding=(16, 12, 16, 8))
        head.pack(fill="x")
        tk.Label(head, text=step, bg=_mix(color, COLORS["panel"], 0.16), fg=color,
                 font=(MONO, 9, "bold"), padx=6).pack(side="left")
        ttk.Label(head, text=title, style="Panel.TLabel",
                  font=(FONT_SEMI, 11)).pack(side="left", padx=(10, 0))
        if hint:
            ttk.Label(head, text=hint, style="Muted.TLabel").pack(side="left", padx=(10, 0))
        body = ttk.Frame(outer, style="Panel.TFrame", padding=(16, 2, 16, 16))
        body.pack(fill="both", expand=True)
        outer.head = head
        return outer, body

    def _note(self, parent, text, **pack):
        label = ttk.Label(parent, text=text, style="Muted.TLabel", wraplength=400)
        label.bind("<Configure>", lambda e: label.configure(wraplength=max(200, e.width - 4)))
        label.pack(anchor="w", fill="x", **pack)
        return label

    def _text_box(self, parent, height=None, wrap="word", mono=True, scroll_x=False):
        frame = tk.Frame(parent, bg=COLORS["background"], highlightthickness=1,
                         highlightbackground=COLORS["border"], highlightcolor=COLORS["border"])
        options = {"height": height} if height else {}
        text = tk.Text(frame, wrap=wrap, font=(MONO if mono else FONT, 10),
                       bg=COLORS["background"], fg=COLORS["text"], insertbackground=COLORS["text"],
                       selectbackground=COLORS["selection"], relief="flat", bd=0,
                       padx=12, pady=10, **options)
        ys = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=ys.set)
        if scroll_x:
            xs = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
            text.configure(xscrollcommand=xs.set)
            xs.pack(side="bottom", fill="x")
        ys.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        for name, accent in (("error", "Rose"), ("success", "Green"), ("warn", "Amber"),
                             ("progress", "Sky"), ("violet", "Violet")):
            text.tag_configure(name, foreground=ACCENTS[accent][0])
        text.tag_configure("time", foreground=COLORS["border"])
        return frame, text

    def _tree_box(self, parent):
        frame = tk.Frame(parent, bg=COLORS["panel"], highlightthickness=1,
                         highlightbackground=COLORS["border"], highlightcolor=COLORS["border"])
        tree = ttk.Treeview(frame, show="tree", selectmode="browse")
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        ys.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        return frame, tree

    # ---------- 01 Phân tích ----------
    def _build_analysis_ui(self, page):
        self._page_header(page, 0, "Phân tích gói Android",
                          "Kéo APK vào, chọn nhóm mã cần giải mã rồi bấm PHÂN TÍCH.")
        grid = ttk.Frame(page)
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=2, uniform="cols")
        grid.columnconfigure(1, weight=3, uniform="cols")
        grid.rowconfigure(1, weight=1)
        page.drop_target_register(DND_FILES)
        page.dnd_bind("<<Drop>>", self._on_drop)

        # Bước 1: đầu vào
        card, left = self._card(grid, "1", "Đầu vào", "Green")
        card.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 14))
        green, green_hover = ACCENTS["Green"]
        drop_bg = _mix(green, COLORS["panel"], 0.06)
        self.drop = tk.Label(left, text="Thả file APK / XAPK / APKS vào đây\nhoặc bấm để chọn file",
                             height=4, bg=drop_bg, fg=COLORS["text"], cursor="hand2",
                             font=(FONT_SEMI, 11), relief="flat", bd=0,
                             highlightbackground=_mix(green, COLORS["panel"], 0.45),
                             highlightcolor=green, highlightthickness=1)
        self.drop.pack(fill="x", ipady=6, pady=(4, 0))
        self.drop.bind("<Button-1>", lambda _: self._pick_inputs())
        def drop_state(active):
            self.drop.configure(bg=_mix(green, COLORS["panel"], 0.18 if active else 0.06),
                                highlightbackground=green if active
                                else _mix(green, COLORS["panel"], 0.45))
        self.drop.bind("<Enter>", lambda _: drop_state(True))
        self.drop.bind("<Leave>", lambda _: drop_state(False))
        self.drop.drop_target_register(DND_FILES)
        self.drop.dnd_bind("<<DropEnter>>", lambda e: (drop_state(True), e.action)[1])
        self.drop.dnd_bind("<<DropLeave>>", lambda e: (drop_state(False), e.action)[1])
        self.drop.dnd_bind("<<Drop>>", lambda e: (drop_state(False), self._on_drop(e)))

        file_buttons = ttk.Frame(left, style="Panel.TFrame")
        file_buttons.pack(fill="x", pady=(12, 10))
        ttk.Button(file_buttons, text="Chọn APK/XAPK", style="Green.Outline.TButton",
                   command=self._pick_inputs).pack(side="left")
        ttk.Button(file_buttons, text="Xóa danh sách", style="Rose.Outline.TButton",
                   command=self._clear_inputs).pack(side="left", padx=8)
        ttk.Label(file_buttons, textvariable=self.count_var, style="Muted.TLabel").pack(side="right")
        list_frame = tk.Frame(left, bg=COLORS["background"], highlightthickness=1,
                              highlightbackground=COLORS["border"])
        list_frame.pack(fill="both", expand=True)
        self.files = tk.Listbox(list_frame, height=6, bg=COLORS["background"],
                                fg=COLORS["text"], selectbackground=COLORS["selection"],
                                selectforeground=green, relief="flat", bd=0,
                                highlightthickness=0, activestyle="none", font=(MONO, 9))
        files_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.files.yview)
        self.files.configure(yscrollcommand=files_scroll.set)
        files_scroll.pack(side="right", fill="y")
        self.files.pack(side="left", fill="both", expand=True, padx=8, pady=6)
        self._note(left, "Hỗ trợ APK Android, XAPK, APKS hoặc các split APK cùng phiên bản. "
                         "Mã native xuất ra là pseudocode.", pady=(10, 0))

        # Bước 2: cấu hình
        card, right = self._card(grid, "2", "Cấu hình", "Green")
        card.grid(row=0, column=1, sticky="nsew", pady=(0, 14))
        right.columnconfigure(0, weight=1)
        right.columnconfigure(1, weight=1)
        ttk.Label(right, text="THƯ MỤC KẾT QUẢ", style="Field.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w")
        output_row = ttk.Frame(right, style="Panel.TFrame")
        output_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 12))
        ttk.Entry(output_row, textvariable=self.output_var, style="Green.TEntry",
                  font=(MONO, 9)).pack(side="left", fill="x", expand=True)
        ttk.Button(output_row, text="Chọn…", command=self._pick_output).pack(side="left", padx=(8, 0))
        options = ttk.Frame(right, style="Panel.TFrame")
        options.grid(row=2, column=0, sticky="nw", padx=(0, 12))
        ttk.Label(options, text="TÙY CHỌN XUẤT", style="Field.TLabel").pack(anchor="w", pady=(0, 2))
        ttk.Checkbutton(options, text="Tạo thân hàm C (mã native)",
                        style="Green.TCheckbutton", variable=self.full_code_var).pack(anchor="w")
        ttk.Checkbutton(options, text="Trích dữ liệu level Unity → levels.json",
                        style="Green.TCheckbutton", variable=self.level_json_var).pack(anchor="w")
        ttk.Checkbutton(options, text="Giải mã Java/DEX (SDK Android)",
                        style="Green.TCheckbutton", variable=self.jadx_var).pack(anchor="w")
        threads_row = ttk.Frame(options, style="Panel.TFrame")
        threads_row.pack(anchor="w", pady=(6, 0))
        ttk.Label(threads_row, text="SỐ LUỒNG", style="Field.TLabel").pack(side="left")
        ttk.Spinbox(threads_row, from_=1, to=max(1, os.cpu_count() or 1), width=3,
                    textvariable=self.threads_var, font=(MONO, 10, "bold"), justify="center",
                    wrap=False).pack(side="left", padx=(10, 6))
        ttk.Label(threads_row, text=f"/ {os.cpu_count() or 1} nhân", style="Field.TLabel").pack(side="left")
        category_box = ttk.Frame(right, style="Panel.TFrame")
        category_box.grid(row=2, column=1, sticky="nw")
        ttk.Label(category_box, text="NHÓM MÃ CẦN DECOMPILE", style="Field.TLabel").pack(
            anchor="w", pady=(0, 2))
        category_names = {
            "game": "Logic game / code riêng của studio",
            "unity": "Unity và .NET framework",
            "sdk": "SDK + tích hợp quảng cáo, IAP, analytics",
        }
        for key in ("game", "unity", "sdk"):
            ttk.Checkbutton(category_box, text=category_names[key], style="Green.TCheckbutton",
                            variable=self.category_vars[key]).pack(anchor="w")
        native_options = ttk.Frame(right, style="Panel.TFrame")
        native_options.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Checkbutton(native_options, text="Giải mã game native C/C++ (engine riêng)",
                        style="Green.TCheckbutton", variable=self.native_var).pack(anchor="w")
        self._note(native_options, "Ví dụ Gardenscapes. Khi không có Unity IL2CPP, phân tích thư viện .so "
                   "bằng Ghidra. Có thể mất nhiều giờ.", padx=(22, 0))
        note = ttk.Frame(right, style="Panel.TFrame")
        note.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self._note(note, "Tự lưu theo lô. Metadata vẫn giữ đủ class/hàm; pseudocode được tách trong "
                         "classes_c\\game_logic, unity_dotnet, third_party_sdk "
                         "(tự nhận theo DLL chứa class), rồi chia theo "
                         "namespace (xem tab README). Game native lưu trong classes_c\\native.")

        # Bước 3: thực thi + nhật ký
        card, run = self._card(grid, "3", "Thực thi & nhật ký", "Green")
        card.grid(row=1, column=1, sticky="nsew")
        controls = ttk.Frame(run, style="Panel.TFrame")
        controls.pack(fill="x", pady=(2, 12))
        self.start_btn = ttk.Button(controls, text="▶  PHÂN TÍCH", style="Green.TButton",
                                    command=self._start)
        self.start_btn.pack(side="left")
        ttk.Button(controls, text="Tiếp tục job", style="Sky.Outline.TButton",
                   command=self._resume).pack(side="left", padx=(8, 0))
        self.retry_btn = ttk.Button(controls, text="Thử lại hàm lỗi", style="Amber.Outline.TButton",
                                    command=self._retry_failed)
        self.retry_btn.pack(side="left", padx=(8, 0))
        self.cancel_btn = ttk.Button(controls, text="Dừng sau khi lưu", style="Rose.Outline.TButton",
                                     command=self._cancel, state="disabled")
        self.cancel_btn.pack(side="left", padx=(8, 0))
        ttk.Button(card.head, text="Mở thư mục kết quả", style="Sky.Outline.TButton",
                   padding=(10, 3), command=self._open_output).pack(side="right")

        state_row = ttk.Frame(run, style="Panel.TFrame")
        state_row.pack(fill="x")
        self._phase_pills.append(self._make_pill(state_row, COLORS["panel"]))
        self._phase_pills[-1].pack(side="left", anchor="n")
        status = ttk.Label(state_row, textvariable=self.status_var, style="Muted.TLabel", wraplength=400)
        status.bind("<Configure>", lambda e: status.configure(wraplength=max(200, e.width - 4)))
        status.pack(side="left", fill="x", expand=True, padx=(10, 0))
        self.progress = ttk.Progressbar(run, mode="indeterminate", style="Green.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(10, 12))
        log_frame, self.log = self._text_box(run, height=6)
        self.log.configure(state="disabled")
        log_frame.pack(fill="both", expand=True)

    # ---------- 02 Duyệt mã ----------
    def _build_browser_ui(self, browser):
        sky = ACCENTS["Sky"][0]
        header = self._page_header(browser, 1, "Duyệt class, phương thức và pseudocode",
                                   "Mở job có methods.sqlite, gõ để lọc class, chọn hàm để xem thân hàm.")
        actions = ttk.Frame(header)
        actions.place(relx=1.0, rely=1.0, anchor="se")
        ttk.Button(actions, text="Mở job", style="Sky.TButton",
                   command=self._pick_job_to_browse).pack(side="left")
        self.csharp_btn = ttk.Button(actions, text="Dịch C → C#", style="Violet.Outline.TButton",
                                     command=self._convert_c_to_csharp)
        self.csharp_btn.pack(side="left", padx=(8, 0))

        search_row = tk.Frame(browser, bg=COLORS["panel"], highlightthickness=1,
                              highlightbackground=COLORS["border"])
        search_row.pack(fill="x", pady=(0, 12))
        tk.Frame(search_row, bg=sky, width=3).pack(side="left", fill="y")
        tk.Label(search_row, text="TÌM CLASS", bg=COLORS["panel"], fg=sky,
                 font=(FONT_SEMI, 9)).pack(side="left", padx=(14, 10))
        ttk.Entry(search_row, textvariable=self.search_var, style="Sky.TEntry",
                  font=(MONO, 10)).pack(side="left", fill="x", expand=True, pady=8, padx=(0, 14))
        self.search_var.trace_add("write", self._search_changed)

        panes = ttk.PanedWindow(browser, orient="horizontal")
        panes.pack(fill="both", expand=True)
        class_card, class_body = self._card(panes, "A", "Class", "Sky")
        method_card, method_body = self._card(panes, "B", "Phương thức", "Sky")
        code_card, code_body = self._card(panes, "C", "Pseudocode C", "Sky")
        for card, count in ((class_card, self.class_count_var), (method_card, self.method_count_var)):
            tk.Label(card.head, textvariable=count, bg=_mix(sky, COLORS["panel"], 0.12), fg=sky,
                     font=(MONO, 8), padx=6).pack(side="right")
        panes.add(class_card, weight=2)
        panes.add(method_card, weight=2)
        panes.add(code_card, weight=5)
        frame, self.class_tree = self._tree_box(class_body)
        frame.pack(fill="both", expand=True)
        self.class_tree.bind("<<TreeviewSelect>>", self._class_selected)
        frame, self.method_tree = self._tree_box(method_body)
        frame.pack(fill="both", expand=True)
        self.method_tree.bind("<<TreeviewSelect>>", self._method_selected)
        frame, self.code = self._text_box(code_body, wrap="none", scroll_x=True)
        frame.pack(fill="both", expand=True)
        palette = {"c_keyword": ACCENTS["Violet"][0], "c_type": sky, "c_number": ACCENTS["Amber"][0],
                   "c_string": ACCENTS["Green"][0], "c_call": "#F0ABFC", "c_comment": COLORS["muted"],
                   "meta_key": COLORS["muted"]}
        for tag, color in palette.items():
            self.code.tag_configure(tag, foreground=color)
        self.code.tag_configure("meta_value", foreground=COLORS["text"], font=(MONO, 10, "bold"))
        self.code.tag_configure("rule", foreground=COLORS["border"])

    # ---------- 04 API ----------
    def _build_api_ui(self, tab):
        card, connection = self._card(tab, "1", "Kết nối API", "Violet",
                                      "Chat Completions tương thích OpenAI")
        card.pack(fill="x")
        connection.columnconfigure(1, weight=1)
        for row, (label, variable) in enumerate([
            ("BASE URL", self.api_url_var), ("API KEY", self.api_key_var),
            ("MODEL", self.api_model_var), ("TIMEOUT (GIÂY)", self.api_timeout_var),
            ("LUỒNG SONG SONG", self.api_workers_var),
        ], 1):
            ttk.Label(connection, text=label, style="Field.TLabel").grid(
                row=row, column=0, sticky="w", padx=(0, 14))
            entry = ttk.Entry(connection, textvariable=variable, style="Violet.TEntry",
                              font=(MONO, 10), show="*" if row == 2 else "")
            entry.grid(row=row, column=1, sticky="ew", pady=3)
            if row == 2:
                show_key = tk.BooleanVar(value=False)
                ttk.Checkbutton(connection, text="Hiện key", variable=show_key, style="Violet.TCheckbutton",
                                command=lambda e=entry, v=show_key: e.configure(show="" if v.get() else "*")).grid(
                                    row=row, column=2, sticky="w", padx=(10, 0))
        self.api_test_btn = ttk.Button(connection, text="Kiểm tra kết nối", style="Violet.Outline.TButton",
                                       command=self._test_api)
        self.api_test_btn.grid(row=4, column=2, sticky="w", padx=(10, 0))
        note = ttk.Frame(connection, style="Panel.TFrame")
        note.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self._note(note, "Nhập đúng model của nhà cung cấp. Key chỉ giữ trong phiên; hỗ trợ DUCAPK_API_KEY. "
                         "Nút kiểm tra gửi một yêu cầu nhỏ và có thể tính phí. Luồng song song (1–16) "
                         "gửi nhiều file cùng lúc; giảm xuống nếu API báo HTTP 429.")

        card, form = self._card(tab, "2", "Nguồn & đích", "Violet", "Dịch C → C# / hoàn thiện C#")
        card.pack(fill="x", pady=(14, 0))
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="NGUỒN .C / .CS", style="Field.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 14))
        ttk.Entry(form, textvariable=self.api_source_var, style="Violet.TEntry",
                  font=(MONO, 10)).grid(row=1, column=1, sticky="ew", pady=3)
        ttk.Button(form, text="Chọn file", command=self._pick_api_file).grid(row=1, column=2, padx=8)
        ttk.Button(form, text="Chọn thư mục", command=self._pick_api_folder).grid(row=1, column=3)
        ttk.Label(form, text="NƠI LƯU KẾT QUẢ", style="Field.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 14))
        ttk.Entry(form, textvariable=self.api_output_var, style="Violet.TEntry",
                  font=(MONO, 10)).grid(row=2, column=1, sticky="ew", pady=3)
        ttk.Button(form, text="Chọn nơi lưu", command=self._pick_api_output).grid(
            row=2, column=2, columnspan=2, sticky="w", padx=8)
        ttk.Label(form, text="YÊU CẦU THÊM", style="Field.TLabel").grid(
            row=3, column=0, sticky="nw", padx=(0, 14), pady=(8, 0))
        instructions_frame, self.api_instructions = self._text_box(form, height=3, mono=False)
        instructions_frame.grid(row=3, column=1, columnspan=3, sticky="ew", pady=(6, 0))
        ttk.Checkbutton(form, text="Bỏ qua _CompilerGenerated (anonymous type, closure — không có logic game)",
                        variable=self.api_skip_generated_var, style="Violet.TCheckbutton").grid(
                            row=4, column=1, columnspan=3, sticky="w", pady=(6, 0))
        note = ttk.Frame(form, style="Panel.TFrame")
        note.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        self._note(note, "Khi bấm dịch, nội dung file được gửi đến API đã nhập và có thể tính phí. "
                         "Kết quả lưu trong thư mục mới; cần rà TODO và biên dịch. File tối đa 240 KB, "
                         "không tự suy đoán logic thiếu. Muốn dịch tiếp lượt cũ: chọn NƠI LƯU là "
                         "chính thư mục kết quả cũ (có api_translation_report.json), file đã xong sẽ được giữ.")

        card, run = self._card(tab, "3", "Thực thi", "Violet")
        card.pack(fill="both", expand=True, pady=(14, 4))
        actions = ttk.Frame(run, style="Panel.TFrame")
        actions.pack(fill="x", pady=(2, 10))
        self.api_start_btn = ttk.Button(actions, text="▶  DỊCH BẰNG API", style="Violet.TButton",
                                        command=self._start_api)
        self.api_start_btn.pack(side="left")
        ttk.Button(actions, text="Dùng classes_c của job", style="Sky.Outline.TButton",
                   command=self._use_job_for_api).pack(side="left", padx=(8, 0))
        self.api_stop_btn = ttk.Button(actions, text="Dừng sau file hiện tại", style="Rose.Outline.TButton",
                                       command=self._stop_api, state="disabled")
        self.api_stop_btn.pack(side="left", padx=(8, 0))
        self.api_open_btn = ttk.Button(actions, text="Mở kết quả", style="Green.Outline.TButton",
                                       command=self._open_api_result, state="disabled")
        self.api_open_btn.pack(side="right")
        status = ttk.Label(run, textvariable=self.api_status_var, style="Panel.TLabel", wraplength=600)
        status.bind("<Configure>", lambda e: status.configure(wraplength=max(200, e.width - 4)))
        status.pack(anchor="w", fill="x")
        self.api_progress = ttk.Progressbar(run, mode="determinate", style="Violet.Horizontal.TProgressbar")
        self.api_progress.pack(fill="x", pady=(8, 10))
        log_frame, self.api_log = self._text_box(run, height=8)
        self.api_log.configure(state="disabled")
        log_frame.pack(fill="both", expand=True)

    # ---------- 06 Level Editor ----------
    def _build_level_editor_ui(self, page):
        self._page_header(page, 5, "Tạo Level Editor HTML từ APK và LevelData.cs",
                          "Đọc cơ chế game (enum, class, level mẫu) trong APK, lấy schema từ LevelData.cs "
                          "và sinh levelEditor.html để xếp level, xuất JSON đúng định dạng.")
        card, form = self._card(page, "1", "Nguồn", "Pink", "APK cho cơ chế game · LevelData.cs cho schema")
        card.pack(fill="x")
        form.columnconfigure(1, weight=1)
        rows = [
            ("APK / JOB", self.le_source_var, [("Chọn APK…", self._pick_le_apk),
                                               ("Chọn job…", self._pick_le_job),
                                               ("Job đang mở", self._use_job_for_le)]),
            ("LEVELDATA .CS", self.le_cs_var, [("Chọn file .cs…", self._pick_le_cs),
                                               ("Chọn thư mục…", self._pick_le_cs_folder)]),
            ("FILE HTML", self.le_output_var, [("Lưu thành…", self._pick_le_output)]),
        ]
        for row, (label, variable, buttons) in enumerate(rows):
            ttk.Label(form, text=label, style="Field.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 14))
            ttk.Entry(form, textvariable=variable, style="Pink.TEntry", font=(MONO, 9)).grid(
                row=row, column=1, sticky="ew", pady=3)
            box = ttk.Frame(form, style="Panel.TFrame")
            box.grid(row=row, column=2, sticky="w", padx=(8, 0))
            for text, command in buttons:
                ttk.Button(box, text=text, command=command, padding=(10, 5)).pack(side="left", padx=(0, 6))
        self.le_source_var.trace_add("write", lambda *_: setattr(self, "le_inputs", []))
        ttk.Label(form, text="CLASS GỐC", style="Field.TLabel").grid(row=3, column=0, sticky="w", padx=(0, 14))
        self.le_root_combo = ttk.Combobox(form, textvariable=self.le_root_var, state="readonly",
                                          font=(MONO, 10))
        self.le_root_combo.grid(row=3, column=1, sticky="ew", pady=3)
        ttk.Button(form, text="Đọc lại class", command=self._refresh_le_roots, padding=(10, 5)).grid(
            row=3, column=2, sticky="w", padx=(8, 0))
        note = ttk.Frame(form, style="Panel.TFrame")
        note.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self._note(note, "Chọn APK: DucAPK đọc metadata IL2CPP và trích level (không giải mã thân hàm) vào một job mới "
                         "trong thư mục kết quả. Chọn job đã phân tích để dùng lại dump.cs và levels.json. "
                         "Kiểu LevelData.cs không khai báo (enum, class con) được lấy từ metadata APK. "
                         "Để trống FILE HTML thì lưu levelEditor.html trong job (hoặc cạnh LevelData.cs). "
                         "Bàn chơi tự đoán theo field; chỉnh trong ⚙ Thiết lập bàn chơi rồi xuất levelEditor.profile.json "
                         "đặt cạnh LevelData.cs để lần sau tool tự dùng. Chưa có LevelData.cs: để trống ô đó, tool "
                         "tự tìm class level trong job và sinh leveldata_from_apk/LevelData.cs.")

        card, run = self._card(page, "2", "Tạo editor", "Pink")
        card.pack(fill="both", expand=True, pady=(14, 4))
        actions = ttk.Frame(run, style="Panel.TFrame")
        actions.pack(fill="x", pady=(2, 10))
        self.le_start_btn = ttk.Button(actions, text="▶  TẠO LEVEL EDITOR", style="Pink.TButton",
                                       command=self._start_level_editor)
        self.le_start_btn.pack(side="left")
        self.le_stop_btn = ttk.Button(actions, text="Dừng", style="Rose.Outline.TButton",
                                      command=self._stop_level_editor, state="disabled")
        self.le_stop_btn.pack(side="left", padx=(8, 0))
        self.le_open_btn = ttk.Button(actions, text="Mở levelEditor.html", style="Green.Outline.TButton",
                                      command=self._open_le_result, state="disabled")
        self.le_open_btn.pack(side="right")
        self.le_folder_btn = ttk.Button(actions, text="Mở thư mục", style="Sky.Outline.TButton",
                                        command=self._open_le_folder, state="disabled")
        self.le_folder_btn.pack(side="right", padx=(0, 8))
        status = ttk.Label(run, textvariable=self.le_status_var, style="Panel.TLabel", wraplength=600)
        status.bind("<Configure>", lambda e: status.configure(wraplength=max(200, e.width - 4)))
        status.pack(anchor="w", fill="x")
        self.le_progress = ttk.Progressbar(run, mode="indeterminate", style="Pink.Horizontal.TProgressbar")
        self.le_progress.pack(fill="x", pady=(8, 10))
        log_frame, self.le_log = self._text_box(run, height=8)
        self.le_log.configure(state="disabled")
        log_frame.pack(fill="both", expand=True)
        page.drop_target_register(DND_FILES)
        page.dnd_bind("<<Drop>>", self._on_le_drop)

    def _on_le_drop(self, event):
        apks = []
        for raw in self.tk.splitlist(event.data):
            path = Path(raw)
            if path.suffix.lower() == ".cs" or (path.is_dir() and not (path / "job.json").is_file()
                                                 and any(path.glob("*.cs"))):
                self._set_le_cs(path)
            elif path.is_dir():
                self._set_le_sources([path])
            elif path.suffix.lower() in {".apk", ".xapk", ".apks", ".zip"}:
                apks.append(path)
        if apks:
            self._set_le_sources(apks)

    def _set_le_sources(self, paths: list[Path]):
        self.le_source_var.set("; ".join(str(path) for path in paths))
        self.le_inputs = paths

    def _set_le_cs(self, path: Path):
        self.le_cs_var.set(str(path))
        self._refresh_le_roots()

    def _pick_le_apk(self):
        selected = filedialog.askopenfilenames(title="Chọn APK/XAPK (hoặc các split APK cùng phiên bản)",
                                               filetypes=[("Android packages", "*.apk *.xapk *.apks *.zip"),
                                                          ("All files", "*.*")])
        if selected:
            self._set_le_sources([Path(name) for name in selected])

    def _pick_le_job(self):
        directory = filedialog.askdirectory(title="Chọn job DucAPK đã phân tích")
        if directory:
            self._set_le_sources([Path(directory)])

    def _use_job_for_le(self):
        if self.job and self.job.is_dir():
            self._set_le_sources([self.job])
        else:
            messagebox.showinfo("Chưa có job", "Phân tích một APK hoặc mở job trong tab Duyệt mã trước.")

    def _pick_le_cs(self):
        path = filedialog.askopenfilename(title="Chọn LevelData.cs", filetypes=[("C#", "*.cs")])
        if path:
            self._set_le_cs(Path(path))

    def _pick_le_cs_folder(self):
        path = filedialog.askdirectory(title="Chọn thư mục chứa LevelData.cs và class liên quan")
        if path:
            self._set_le_cs(Path(path))

    def _pick_le_output(self):
        path = filedialog.asksaveasfilename(title="Lưu level editor", defaultextension=".html",
                                            initialfile="levelEditor.html", filetypes=[("HTML", "*.html")])
        if path:
            self.le_output_var.set(path)

    def _refresh_le_roots(self):
        text = self.le_cs_var.get().strip()
        values: list[str] = []
        if text:
            try:
                values = root_candidates(read_leveldata(leveldata_sources(Path(text))))
            except (OSError, ValueError) as error:
                self.le_status_var.set(f"Không đọc được LevelData: {error}")
                return
        self.le_root_combo.configure(values=values)
        if values and self.le_root_var.get() not in values:
            self.le_root_var.set(values[0])
        if text:
            self.le_status_var.set(f"Đọc {len(values)} class trong LevelData; class gốc: {self.le_root_var.get()}"
                                   if values else "LevelData chưa có class/struct nào đọc được.")

    def _set_le_busy(self, busy: bool):
        self.le_start_btn.configure(state="disabled" if busy else "normal")
        self.le_stop_btn.configure(state="normal" if busy else "disabled")
        if busy:
            self.le_progress.start(10)
        else:
            self.le_progress.stop()
            self.le_progress.configure(value=0)

    def _start_level_editor(self):
        if self.le_worker and self.le_worker.is_alive():
            return
        cs_text = self.le_cs_var.get().strip()
        inputs = self.le_inputs or [Path(part.strip()) for part in self.le_source_var.get().split(";")
                                    if part.strip()]
        if cs_text and not leveldata_sources(Path(cs_text)):
            messagebox.showinfo("Thiếu LevelData", f"Không có file .cs trong {cs_text}.")
            return
        if not cs_text and not inputs:
            messagebox.showinfo("Thiếu LevelData", "Chọn LevelData.cs, hoặc chọn APK/job để tool tự suy ra LevelData "
                                                   "từ metadata của game.")
            return
        missing = [path for path in inputs if not path.exists()]
        if missing:
            messagebox.showerror("Không tìm thấy", "\n".join(str(path) for path in missing))
            return
        if cs_text and not inputs and not messagebox.askyesno(
                "Chưa chọn APK", "Không có APK/job: editor chỉ dùng LevelData.cs, không có enum/level "
                                 "từ game. Tiếp tục?"):
            return
        output = Path(self.le_output_var.get().strip()) if self.le_output_var.get().strip() else None
        self.le_cancel.clear()
        self._set_le_busy(True)
        self.phase_var.set("LEVEL EDITOR")
        self.le_status_var.set("Đang chuẩn bị…")
        self.le_worker = threading.Thread(
            target=self._run_level_editor,
            args=(inputs, Path(cs_text) if cs_text else None, self.le_root_var.get() or None, output,
                  Path(self.output_var.get())), daemon=True)
        self.le_worker.start()

    def _run_level_editor(self, inputs: list[Path], leveldata: Path | None, root: str | None,
                          output: Path | None, output_root: Path):
        emit = lambda message: self.events.put(("le_log", message))
        try:
            job = None
            if len(inputs) == 1 and inputs[0].is_dir():
                job = inputs[0].resolve()
                if not ((job / "job.json").is_file() or (job / "il2cppdumper").is_dir()
                        or (job / "levels.json").is_file()):
                    raise LevelEditorError(f"Thư mục không phải job DucAPK: {job}")
                emit(f"Dùng job đã phân tích: {job}")
            elif inputs:
                emit("BẮT ĐẦU đọc APK: metadata + level (không giải mã thân hàm)…")
                job = analyze(inputs, output_root, emit, self.le_cancel, with_ghidra=False,
                              extract_levels=True, decompile_java=False)
            if output is None:
                output = (job / "levelEditor.html") if job else leveldata.parent / "levelEditor.html"
            report = build_level_editor(leveldata, output, job, root, emit, self.le_cancel)
            self.events.put(("le_done", report, job))
        except AnalysisCancelled as error:
            self.events.put(("le_error", "Đã dừng: " + str(error)))
        except Exception as error:
            self.events.put(("le_error", str(error)))

    def _stop_level_editor(self):
        self.le_cancel.set()
        self.le_status_var.set("Đang dừng; chờ bước hiện tại lưu xong…")
        self.le_stop_btn.configure(state="disabled")

    def _open_le_result(self):
        if self.le_result and self.le_result.is_file():
            os.startfile(self.le_result)

    def _open_le_folder(self):
        if self.le_result and self.le_result.parent.is_dir():
            os.startfile(self.le_result.parent)

    def _le_message(self, message: str):
        self.le_status_var.set(message)
        self._append_log(self.le_log, message)

    @staticmethod
    def _log_tag(message: str) -> str | None:
        upper = message.upper()
        if upper.startswith("LỖI") or "LỖI API" in upper or "LỖI DỊCH" in upper:
            return "error"
        if upper.startswith(("HOÀN TẤT", "XONG", "ĐÃ XUẤT", "KẾT THÚC", "DỊCH C → C# XONG", "KHỚP APK")) \
                or "ĐÃ CÓ PSEUDOCODE" in upper:
            return "success"
        if upper.startswith(("ĐÃ DỪNG", "ĐANG DỪNG", "TRẠNG THÁI", "KHÁC APK", "CHƯA XÁC ĐỊNH")):
            return "warn"
        if "DUCAPK_PROGRESS" in message or upper.startswith("BẮT ĐẦU"):
            return "progress"
        return None

    def _append_log(self, widget: tk.Text, message: str):
        widget.configure(state="normal")
        widget.insert("end", f"{datetime.now():%H:%M:%S}  ", "time")
        tag = self._log_tag(message)
        widget.insert("end", message + "\n", (tag,) if tag else ())
        widget.see("end")
        widget.configure(state="disabled")

    def _pick_api_file(self):
        path = filedialog.askopenfilename(title="Chọn mã C hoặc C#", filetypes=[("C / C#", "*.c *.cs")])
        if path:
            self.api_source_var.set(path)

    def _pick_api_folder(self):
        path = filedialog.askdirectory(title="Chọn thư mục mã C / C# (đọc cả thư mục con)")
        if path:
            self.api_source_var.set(path)

    def _pick_api_output(self):
        path = filedialog.askdirectory(title="Chọn thư mục cha lưu kết quả API")
        if path:
            self.api_output_var.set(path)

    def _use_job_for_api(self):
        if self.job and (self.job / "classes_c").is_dir():
            self.api_source_var.set(str(self.job / "classes_c"))
        else:
            messagebox.showinfo("Chọn job", "Mở job có classes_c trong tab Duyệt mã trước.")

    def _open_api_result(self):
        if self.api_result and self.api_result.is_dir():
            os.startfile(self.api_result)

    def _api_config(self):
        config = APIConfig(self.api_url_var.get().strip(), self.api_model_var.get().strip(),
                           self.api_key_var.get().strip(), int(self.api_timeout_var.get()))
        config.validate()
        return config

    def _set_api_busy(self, busy, testing=False):
        self.api_start_btn.configure(state="disabled" if busy else "normal")
        self.api_test_btn.configure(state="disabled" if busy else "normal")
        self.api_stop_btn.configure(state="normal" if busy and not testing else "disabled")

    def _test_api(self):
        if self.api_worker and self.api_worker.is_alive():
            return
        try:
            config = self._api_config()
        except ValueError as error:
            messagebox.showerror("Cấu hình API", str(error))
            return
        self._set_api_busy(True, testing=True)
        self.api_status_var.set("Đang kiểm tra API/model…")
        def run():
            try:
                self.events.put(("api_test_done", test_connection(config)))
            except Exception as error:
                self.events.put(("api_error", str(error)))
        self.api_worker = threading.Thread(target=run, daemon=True)
        self.api_worker.start()

    def _start_api(self):
        if self.api_worker and self.api_worker.is_alive():
            return
        try:
            config = self._api_config()
            if not self.api_source_var.get().strip() or not self.api_output_var.get().strip():
                raise ValueError("Chọn đầu vào và nơi lưu kết quả.")
            source = Path(self.api_source_var.get().strip()).resolve()
            if not source.exists() or (source.is_file() and source.suffix.lower() not in {".c", ".cs"}):
                raise ValueError("Đầu vào phải là file .c/.cs hoặc thư mục tồn tại.")
            output = Path(self.api_output_var.get().strip()).resolve()
            resume = is_resumable(output)
            destination = output if resume else output / (
                f"{source.stem}_API_CSharp_{datetime.now():%Y%m%d_%H%M%S_%f}")
            if source.is_dir() and source in destination.parents:
                raise ValueError("Chọn nơi lưu nằm ngoài thư mục nguồn.")
            try:
                workers = int(self.api_workers_var.get())
            except ValueError:
                raise ValueError("Luồng song song phải là số từ 1 đến 16.") from None
        except ValueError as error:
            messagebox.showerror("API dịch mã", str(error))
            return
        if resume:
            self._api_message(f"Tiếp tục lượt cũ trong {destination}; file đã dịch xong sẽ được giữ.")
        skip_generated = self.api_skip_generated_var.get()
        instructions = self.api_instructions.get("1.0", "end").strip()
        self.api_cancel.clear()
        self._set_api_busy(True)
        self.api_status_var.set("Đang tìm file và khởi tạo dịch API…")
        self.api_progress.configure(value=0)
        def run():
            try:
                report = export_api(source, destination, config, instructions, self.api_cancel,
                                    lambda done, total, msg: self.events.put(("api_progress", done, total, msg)),
                                    workers=workers, skip_compiler_generated=skip_generated, resume=resume)
                self.events.put(("api_done", destination, report))
            except Exception as error:
                self.events.put(("api_error", str(error)))
        self.api_worker = threading.Thread(target=run, daemon=True)
        self.api_worker.start()

    def _stop_api(self):
        self.api_cancel.set()
        self.api_status_var.set("Đang dừng; chờ API hoàn tất file hiện tại hoặc hết timeout.")
        self.api_stop_btn.configure(state="disabled")

    def _api_message(self, message):
        self.api_status_var.set(message)
        self._append_log(self.api_log, message)

    def _on_drop(self, event):
        for raw in self.tk.splitlist(event.data):
            path = Path(raw)
            if path.exists() and path not in self.inputs:
                self.inputs.append(path)
                self.files.insert("end", str(path))
        self.count_var.set(f"{len(self.inputs)} gói được chọn")
        self.status_var.set(f"Đã chọn {len(self.inputs)} đầu vào.")

    def _pick_inputs(self):
        selected = filedialog.askopenfilenames(title="Chọn APK/XAPK hoặc split APK",
                                               filetypes=[("Android packages", "*.apk *.xapk *.apks *.zip"),
                                                          ("All files", "*.*")])
        for name in selected:
            path = Path(name)
            if path not in self.inputs:
                self.inputs.append(path)
                self.files.insert("end", str(path))
        self.count_var.set(f"{len(self.inputs)} gói được chọn")

    def _clear_inputs(self):
        self.inputs.clear()
        self.files.delete(0, "end")
        self.count_var.set("0 gói được chọn")

    def _pick_output(self):
        directory = filedialog.askdirectory(title="Chọn nơi lưu kết quả")
        if directory:
            self.output_var.set(directory)

    def _native_progress(self, message: str):
        """Cập nhật thanh tiến trình theo từng hàm; chỉ ghi log mỗi 25 hàm để không tràn."""
        current_line = "DUCAPK_CURRENT " in message
        marker = "DUCAPK_CURRENT " if current_line else "DUCAPK_PROGRESS "
        payload = message.split(marker, 1)[1].removesuffix("(GhidraScript)").strip()
        counter, _, rest = payload.partition(" ")
        try:
            current, total = (int(n) for n in counter.split("/"))
        except ValueError:
            return
        self.phase_var.set("GIẢI MÃ NATIVE")
        self.native_tick = time.monotonic()
        if current_line:
            self.native_function = rest
            self.native_position = (current, total)
        else:
            self.native_ok = rest.removeprefix("ok=")
            self.native_eta.update(current, total, time.monotonic())
            self.progress.stop()
            self.progress.configure(mode="determinate", maximum=total, value=current)
            self.native_position = (current, total)
            if current % 25 == 0 or current == total:
                self._append_log(self.log, message)
        self._native_status()

    def _reset_native_progress(self):
        self.native_position: tuple[int, int] | None = None
        self.native_function = ""
        self.native_ok = "0"
        self.native_tick = time.monotonic()
        self.native_eta = ProgressEta()

    def _native_status(self):
        if not self.native_position:
            return
        current, total = self.native_position
        text = (f"Giải mã native {current:,}/{total:,} ({current / max(1, total):.2%})"
                f" · thành công {self.native_ok}")
        remaining = self.native_eta.remaining_seconds()
        if remaining is None:
            text += " · đang đo tốc độ…"
        else:
            text += (f" · {self.native_eta.rate():.1f} hàm/s · còn ~{format_duration(remaining)}"
                     f" (xong ~{finish_clock(remaining)})")
        if self.native_function:
            text += f" · đang xử lý {self.native_function[:120]}"
        waited = time.monotonic() - self.native_tick
        if waited >= 3:
            text += f" · đã chờ {int(waited)}s (hàm nặng, tối đa 30s mỗi hàm)"
        self.status_var.set(text)

    def _log(self, message: str):
        if "DUCAPK_PROGRESS " in message or "DUCAPK_CURRENT " in message:
            self._native_progress(message)
            return
        self.native_position = None
        self._append_log(self.log, message)
        self.status_var.set(message)
        if message.startswith("Đọc gói") or "Đã lấy arm64" in message:
            self.phase_var.set("ĐỌC GÓI APK")
        elif "metadata" in message.lower() or "Đã nhóm" in message:
            self.phase_var.set("GHÉP CLASS VÀ HÀM")
        elif "Ghidra" in message or "DUCAPK_PROGRESS" in message:
            self.phase_var.set("GIẢI MÃ NATIVE")
        elif "Đã ghi" in message:
            self.phase_var.set("XUẤT CLASS")
        elif message.startswith("HOÀN TẤT") or message.startswith("Xong:"):
            self.phase_var.set("HOÀN TẤT")
        elif message.startswith("LỖI"):
            self.phase_var.set("LỖI")

    def _run(self, inputs: list[Path], resume: Path | None,
             with_ghidra: bool, output_root: Path,
             include_categories: set[str] | None, extract_levels: bool,
             decompile_java: bool, decompile_native: bool):
        try:
            job = analyze(inputs, output_root,
                          lambda msg: self.events.put(("log", msg)), self.cancel,
                          with_ghidra=with_ghidra, resume_job=resume,
                          include_categories=include_categories,
                          extract_levels=extract_levels, decompile_java=decompile_java,
                          decompile_native=decompile_native)
            self.events.put(("done", job))
        except AnalysisCancelled as error:
            self.events.put(("cancelled", str(error)))
        except Exception as error:
            self.events.put(("error", str(error)))

    def _apply_threads(self):
        """Đọc ô số luồng; giá trị sai thì trả về mặc định của máy."""
        try:
            count = max(1, int(self.threads_var.get()))
        except ValueError:
            count = DEFAULT_GHIDRA_THREADS
        self.threads_var.set(str(count))
        set_ghidra_threads(count)

    def _run_retry_failed(self, job: Path):
        try:
            report = retry_failed_only(
                job, lambda msg: self.events.put(("log", msg)), self.cancel)
            self.events.put(("retry_done", job, report))
        except AnalysisCancelled as error:
            self.events.put(("cancelled", str(error)))
        except Exception as error:
            self.events.put(("error", str(error)))

    def _start_worker(self, inputs: list[Path], resume: Path | None = None):
        if self.worker and self.worker.is_alive():
            return
        if resume is not None:
            self.job = resume.resolve()
        self._apply_threads()
        self.cancel.clear()
        self._reset_native_progress()
        self.phase_var.set("ĐANG KHỞI TẠO")
        self.start_btn.configure(state="disabled")
        self.retry_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress.configure(mode="indeterminate")
        self.progress.start(10)
        selected_categories = ({key for key, variable in self.category_vars.items()
                                if variable.get()} if resume is None else None)
        if resume is None and self.full_code_var.get() and not selected_categories:
            self.progress.stop()
            self.start_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.retry_btn.configure(state="normal" if self.job is None else "disabled")
            if self.job and (self.job / "methods.sqlite").is_file():
                self._load_job(self.job)
            messagebox.showinfo("Chọn nhóm mã", "Chọn ít nhất một nhóm mã để giải mã.")
            return
        self.worker = threading.Thread(target=self._run,
                                       args=(inputs, resume, self.full_code_var.get(),
                                             Path(self.output_var.get()),
                                             selected_categories,
                                             self.level_json_var.get(),
                                             self.jadx_var.get(), self.native_var.get()), daemon=True)
        self.worker.start()

    def _start(self):
        if not self.inputs:
            messagebox.showinfo("Chọn APK", "Kéo APK/XAPK vào cửa sổ hoặc bấm Chọn APK/XAPK.")
            return
        self._start_worker(list(self.inputs))

    def _resume(self):
        directory = filedialog.askdirectory(title="Chọn thư mục job DucAPK đã tạo")
        if directory:
            self._start_worker([], Path(directory))

    def _retry_failed(self):
        if self.worker and self.worker.is_alive():
            return
        job = self.job
        if job is None or not (job / "job.json").is_file():
            directory = filedialog.askdirectory(title="Chọn job cần thử lại hàm lỗi")
            if not directory:
                return
            job = Path(directory)
        self.job = job.resolve()
        self.cancel.clear()
        self._reset_native_progress()
        self.start_btn.configure(state="disabled")
        self.retry_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.phase_var.set("THỬ LẠI HÀM LỖI")
        self.progress.configure(mode="indeterminate")
        self.progress.start(10)
        if self.database is not None:
            self.database.close()
            self.database = None
        self._apply_threads()
        self.worker = threading.Thread(target=self._run_retry_failed, args=(job,), daemon=True)
        self.worker.start()

    def _cancel(self):
        self.cancel.set()
        self._log("Đang dừng; chờ tiến trình hiện tại đóng và lưu dữ liệu...")

    def _pump(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "api_progress":
                    self.api_progress.configure(maximum=max(1, event[2]), value=event[1])
                    self._api_message(event[3])
                elif event[0] == "api_test_done":
                    self._set_api_busy(False)
                    self._api_message(event[1])
                elif event[0] == "api_done":
                    self._set_api_busy(False)
                    self.api_result, report = event[1], event[2]
                    self.api_open_btn.configure(state="normal")
                    state = "ĐÃ DỪNG" if report['cancelled'] or report.get('stopped_on_api_error') else "HOÀN TẤT"
                    self._api_message(f"{state}: {report['files_written']}/{report['files_found']} file đã lưu, "
                                      f"{report['files_failed']} lỗi, {report['files_pending']} chưa xử lý. "
                                      f"Kết quả và báo cáo: {self.api_result}")
                elif event[0] == "api_error":
                    self._set_api_busy(False)
                    self._api_message("LỖI API: " + event[1])
                    messagebox.showerror("API dịch mã", event[1])
                elif event[0] == "le_log":
                    self._le_message(event[1])
                elif event[0] == "le_done":
                    self._set_le_busy(False)
                    report, job = event[1], event[2]
                    self.le_result = Path(report["output"])
                    self.le_open_btn.configure(state="normal")
                    self.le_folder_btn.configure(state="normal")
                    if job is not None:
                        self.job = job
                    if report["inferred_candidates"]:
                        self.le_root_combo.configure(values=[k.split(".")[-1] for k in report["inferred_candidates"]])
                        self.le_root_var.set(report["root"].split(".")[-1])
                        self._le_message(f"LevelData suy ra từ APK: {report['leveldata']}. Đoán sai class level thì chọn "
                                         "class khác ở CLASS GỐC (để trống LEVELDATA) rồi tạo lại.")
                    self.phase_var.set("HOÀN TẤT")
                    self._le_message(
                        f"HOÀN TẤT: {report['classes']} class, {report['enums']} enum "
                        f"({report['apk_types_used']} kiểu lấy từ APK), {report['mechanic_enums']} enum cơ chế, "
                        f"{report['levels_embedded']} level mẫu, {report['unresolved']} kiểu chưa xác định. "
                        f"File: {self.le_result}")
                elif event[0] == "le_error":
                    self._set_le_busy(False)
                    self.phase_var.set("LỖI")
                    self._le_message("LỖI: " + event[1])
                    messagebox.showerror("Level Editor", event[1])
                elif event[0] == "log":
                    self._log(event[1])
                elif event[0] == "csharp_log":
                    self._log(event[1])
                elif event[0] == "csharp_done":
                    destination, report = event[1], event[2]
                    self.csharp_btn.configure(state="normal")
                    self._log("DỊCH C → C# XONG: "
                              f"{report['files_written']:,}/{report['files_found']:,} file, "
                              f"{report['methods_translated']:,} hàm có thân đã chuyển cú pháp, "
                              f"{report['methods_stubbed']:,} hàm còn stub, "
                              f"{report['files_failed']:,} file lỗi. Lưu tại: {destination}")
                    self._log(f"Xem hàm cần rà soát tại: {destination / 'translation_report.json'}")
                elif event[0] == "csharp_error":
                    self.csharp_btn.configure(state="normal")
                    self._log("LỖI DỊCH C → C#: " + event[1])
                    messagebox.showerror("DucAPK", event[1])
                elif event[0] in {"done", "retry_done", "cancelled", "error"}:
                    self._reset_native_progress()
                    self.progress.stop()
                    self.start_btn.configure(state="normal")
                    self.cancel_btn.configure(state="disabled")
                    if event[0] == "done":
                        self.job = event[1]
                        job_info = json.loads((self.job / "job.json").read_text(encoding="utf-8"))
                        report = job_info.get("report", {})
                        if report.get("pseudocode_enabled"):
                            missing = int(report.get("functions_without_body", 0))
                            total = int(report.get("selected_for_decompile", 0))
                            success = int(report.get("functions_with_body", 0))
                            self.phase_var.set("HOÀN TẤT MỘT PHẦN" if missing or report.get("partial") else "HOÀN TẤT")
                            self._log(f"ĐÃ XUẤT KẾT QUẢ: có thân {success:,}/{total:,}; còn lỗi/thiếu thân {missing:,} hàm.")
                            if missing:
                                statuses = report.get("failed_by_status", {})
                                if statuses:
                                    self._log("Trạng thái hàm còn lỗi: " + ", ".join(
                                        f"{name}={count:,}" for name, count in sorted(statuses.items())))
                                self._log(f"Danh sách lỗi: {self.job / 'failed_functions.json'}")
                        elif "pseudocode_enabled" in report and not report["pseudocode_enabled"]:
                            self.phase_var.set("HOÀN TẤT MỘT PHẦN" if report.get("partial") else "HOÀN TẤT")
                            self._log(f"ĐÃ XUẤT METADATA: {report.get('selected_for_decompile', 0):,} phương thức; chưa yêu cầu Ghidra.")
                        elif report.get("backend"):
                            self.phase_var.set("HOÀN TẤT MỘT PHẦN" if report.get("partial") else "HOÀN TẤT")
                            self._log(f"ĐÃ XUẤT {report.get('backend')}: {report.get('java_sources', 0):,} file source.")
                        if (self.job / "methods.sqlite").is_file():
                            self._load_job(self.job)
                        elif (self.job / "java_source" / "sources").is_dir():
                            self.retry_btn.configure(state="disabled")
                            self._log(f"Mã Java/Kotlin đã giải mã tại: {self.job / 'java_source' / 'sources'}")
                    elif event[0] == "retry_done":
                        self.job = event[1]
                        report = event[2]
                        missing = int(report.get("functions_without_body", 0))
                        self.phase_var.set("HOÀN TẤT MỘT PHẦN" if missing or report.get("partial") else "HOÀN TẤT")
                        self._log(f"KẾT THÚC THỬ LẠI: có thân {report.get('functions_with_body', 0):,}/"
                                  f"{report.get('selected_for_decompile', 0):,}; còn lỗi/thiếu thân {missing:,} hàm.")
                        if missing:
                            statuses = report.get("failed_by_status", {})
                            if statuses:
                                self._log("Trạng thái còn lại: " + ", ".join(
                                    f"{name}={count:,}" for name, count in sorted(statuses.items())))
                            self._log(f"Chi tiết: {self.job / 'failed_functions.json'}")
                        else:
                            self._log("Đã có pseudocode cho toàn bộ hàm được chọn.")
                        self._load_job(self.job)
                    elif event[0] == "cancelled":
                        self._log("ĐÃ DỪNG: " + event[1])
                        if self.job and (self.job / "methods.sqlite").is_file():
                            self._load_job(self.job)
                        else:
                            self.retry_btn.configure(state="normal")
                    else:
                        self._log("LỖI: " + event[1])
                        if self.job and (self.job / "methods.sqlite").is_file():
                            self._load_job(self.job)
                        else:
                            self.retry_btn.configure(state="normal")
                        messagebox.showerror("DucAPK", event[1])
        except queue.Empty:
            pass
        # Nhịp đếm giây khi một hàm nặng chưa xong, để thấy tiến trình vẫn đang chạy.
        if self.native_position and self.worker and self.worker.is_alive():
            self._native_status()
        job_text = str(self.job) if self.job else "Chưa mở job"
        if self.job_var.get() != job_text:
            self.job_var.set(job_text)
        self.after(100, self._pump)

    def _open_output(self):
        path = self.job or Path(self.output_var.get())
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(path)

    def _pick_job_to_browse(self):
        directory = filedialog.askdirectory(title="Chọn job có methods.sqlite")
        if directory:
            self._load_job(Path(directory))

    def _convert_c_to_csharp(self):
        if self.csharp_worker and self.csharp_worker.is_alive():
            return
        job = self.job
        if job is None or not (job / "classes_c").is_dir():
            directory = filedialog.askdirectory(title="Chọn job có thư mục classes_c")
            if not directory:
                return
            job = Path(directory).resolve()
        source = job / "classes_c"
        if not source.is_dir():
            messagebox.showerror("Không có pseudocode C", f"Không tìm thấy thư mục:\n{source}")
            return
        export_parent = filedialog.askdirectory(
            title="Chọn ổ hoặc thư mục lưu file C#")
        if not export_parent:
            return
        destination = Path(export_parent) / f"{job.name}_CSharp"
        self.csharp_btn.configure(state="disabled")
        self._log(f"BẮT ĐẦU DỊCH C → C#: đọc {source}; giữ nguyên C; ghi C# ra {destination}")
        self.csharp_worker = threading.Thread(
            target=self._run_csharp_export,
            args=(source, destination), daemon=True)
        self.csharp_worker.start()

    def _run_csharp_export(self, source: Path, destination: Path):
        try:
            report = export_c_tree(
                source, destination,
                lambda message: self.events.put(("csharp_log", message)))
            self.events.put(("csharp_done", destination, report))
        except Exception as error:
            self.events.put(("csharp_error", str(error)))

    def _load_job(self, job: Path):
        database = job / "methods.sqlite"
        if not database.is_file():
            messagebox.showerror("Job chưa có dữ liệu", "Không tìm thấy methods.sqlite trong thư mục đã chọn.")
            return
        if self.database is not None:
            self.database.close()
        self.database = sqlite3.connect(database)
        self.job = job
        with_ghidra = True
        try:
            with_ghidra = bool(json.loads((job / "job.json").read_text(encoding="utf-8"))
                               .get("with_ghidra", True))
        except (OSError, ValueError):
            pass
        failed_count = None
        report_path = job / "report.json"
        if report_path.is_file():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                if "functions_without_body" in report:
                    failed_count = int(report["functions_without_body"])
            except (OSError, ValueError):
                pass
        if failed_count is None:
            try:
                has_selection = self.database.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='selected_methods'").fetchone()
                if has_selection:
                    failed_count = self.database.execute(
                        "SELECT COUNT(*) FROM selected_methods s LEFT JOIN results r "
                        "ON r.export_index=s.export_index WHERE r.status IS NULL OR "
                        "r.status<>'ok' OR TRIM(COALESCE(r.body,''))=''").fetchone()[0]
                else:
                    failed_count = self.database.execute(
                        "SELECT COUNT(*) FROM methods m LEFT JOIN results r "
                        "ON r.export_index=m.export_index WHERE m.export_index IS NOT NULL AND "
                        "(r.status IS NULL OR r.status<>'ok' OR TRIM(COALESCE(r.body,''))='')").fetchone()[0]
            except sqlite3.Error:
                failed_count = 0
        self.retry_btn.configure(state="normal" if with_ghidra and failed_count else "disabled")
        self._refresh_classes()
        self._refresh_tech()

    def _search_changed(self, *_):
        if self.search_after is not None:
            self.after_cancel(self.search_after)
        self.search_after = self.after(220, self._refresh_classes)

    def _refresh_classes(self):
        self.search_after = None
        self.class_tree.delete(*self.class_tree.get_children())
        self.method_tree.delete(*self.method_tree.get_children())
        self.class_count_var.set("0")
        self.method_count_var.set("0")
        if self.database is None:
            return
        query = self.search_var.get().strip()
        if query:
            rows = self.database.execute("SELECT DISTINCT class_name FROM methods "
                                         "WHERE class_name LIKE ? ORDER BY class_name LIMIT 300",
                                         ("%" + query + "%",))
        else:
            rows = self.database.execute("SELECT DISTINCT class_name FROM methods "
                                         "ORDER BY class_name LIMIT 300")
        for index, (name,) in enumerate(rows):
            self.class_tree.insert("", "end", iid=f"c{index}", text=name, values=(name,))
        count = len(self.class_tree.get_children())
        self.class_count_var.set(f"{count}+" if count >= 300 else str(count))

    def _class_selected(self, _):
        selected = self.class_tree.selection()
        if not selected or self.database is None:
            return
        class_name = self.class_tree.item(selected[0], "text")
        self.method_tree.delete(*self.method_tree.get_children())
        rows = self.database.execute("SELECT id, method_name, address FROM methods "
                                     "WHERE class_name=? ORDER BY id", (class_name,))
        for method_id, name, address in rows:
            self.method_tree.insert("", "end", iid=f"m{method_id}",
                                    text=f"{name}  [0x{address:X}]")
        self.method_count_var.set(str(len(self.method_tree.get_children())))

    def _method_selected(self, _):
        selected = self.method_tree.selection()
        if not selected or self.database is None:
            return
        method_id = int(selected[0][1:])
        row = self.database.execute(
            "SELECT m.class_name, m.method_name, m.signature, m.address, "
            "r.status, r.body FROM methods m LEFT JOIN results r "
            "ON m.export_index=r.export_index WHERE m.id=?", (method_id,)).fetchone()
        if row is None:
            return
        class_name, method_name, signature, address, status, body = row
        self.code.delete("1.0", "end")
        status_tag = "c_string" if status == "ok" else "c_number"
        for key, value, tag in (("Class", class_name, "meta_value"), ("Method", method_name, "meta_value"),
                                ("Address/RVA", f"0x{address:X}", "c_number"),
                                ("Signature", signature, "c_type"),
                                ("Status", status or "chưa tạo thân hàm", status_tag)):
            self.code.insert("end", f"{key:<13}", "meta_key")
            self.code.insert("end", f"{value}\n", tag)
        self.code.insert("end", "─" * 72 + "\n\n", "rule")
        start = self.code.index("end-1c")
        body = body or ""
        self.code.insert("end", body)
        if len(body) <= 200_000:
            for tag, pattern in C_PATTERNS:
                for match in re.finditer(pattern, body, re.MULTILINE | re.DOTALL):
                    span = match.span(1) if match.re.groups else match.span()
                    self.code.tag_add(tag, f"{start}+{span[0]}c", f"{start}+{span[1]}c")

    def _close(self):
        if self.le_worker and self.le_worker.is_alive():
            self.le_cancel.set()
            self.le_status_var.set("Đang dừng tạo level editor trước khi đóng…")
            self.after(500, self._wait_to_close)
            return
        if self.api_worker and self.api_worker.is_alive():
            self.api_cancel.set()
            self.api_status_var.set("Đang dừng API trước khi đóng; chờ yêu cầu hiện tại hoàn tất.")
            self.after(500, self._wait_to_close)
            self.cancel.set()
            return
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("Đang phân tích", "Dừng và lưu kết quả hiện có trước khi đóng?"):
                return
            self.cancel.set()
            self.after(500, self._wait_to_close)
            return
        self.tech_view.stop()
        if self.database is not None:
            self.database.close()
        self.destroy()

    def _wait_to_close(self):
        if ((self.worker and self.worker.is_alive())
                or (self.api_worker and self.api_worker.is_alive())
                or (self.le_worker and self.le_worker.is_alive())):
            self.after(500, self._wait_to_close)
        else:
            self.destroy()


if __name__ == "__main__":
    DucAPKApp().mainloop()
