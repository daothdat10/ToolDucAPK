"""Native Tkinter browser for the source-backed DucAPK knowledge graph."""
from __future__ import annotations

import json
from pathlib import Path
import tkinter as tk
from tkinter import ttk


TYPE_LABELS = {
    "application": "Ứng dụng", "interface": "Giao diện", "module": "Module",
    "capability": "Chức năng", "input": "Đầu vào", "dependency": "Phụ thuộc",
    "artifact": "Đầu ra / dữ liệu", "concept": "Khái niệm / định dạng",
    "constraint": "Giới hạn / quy tắc",
}


class KnowledgeGraphView(ttk.Frame):
    def __init__(self, parent, graph_path: Path, colors: dict):
        super().__init__(parent, padding=12)
        self.graph_path, self.colors = graph_path, colors
        self.nodes, self.edges, self.predicates = {}, [], {}
        self.selected = "ducapk"
        self.search = tk.StringVar()
        self.summary = tk.StringVar()
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 10))
        ttk.Label(top, text="THỰC THỂ & QUAN HỆ", foreground=colors["blue"],
                  font=("Segoe UI Semibold", 10)).pack(side="left")
        ttk.Button(top, text="Về DucAPK", command=lambda: self.show_entity("ducapk")).pack(side="right")
        ttk.Button(top, text="Tải lại graph", command=self.reload).pack(side="right", padx=8)
        ttk.Label(self, textvariable=self.summary, wraplength=950).pack(anchor="w", pady=(0, 8))
        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Frame(panes, width=240)
        right = ttk.Frame(panes)
        panes.add(left, weight=1)
        panes.add(right, weight=4)
        ttk.Label(left, text="Tìm thực thể").pack(anchor="w")
        ttk.Entry(left, textvariable=self.search).pack(fill="x", pady=(4, 8))
        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_frame, show="tree", selectmode="browse", height=8)
        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._tree_selected)
        self.search.trace_add("write", self._filter)
        ttk.Label(right, text="Mũi tên: chủ thể → đối tượng. Bấm nút để khám phá; cuộn để xem đầy đủ.",
                  foreground=colors["muted"], wraplength=680).pack(anchor="w", padx=(10, 0), pady=(0, 8))
        diagram = ttk.Frame(right)
        diagram.pack(fill="both", expand=True, padx=(10, 0))
        diagram.rowconfigure(0, weight=1)
        diagram.columnconfigure(0, weight=1)
        self.canvas = tk.Canvas(diagram, bg=colors["background"], highlightthickness=0, height=180)
        ys = ttk.Scrollbar(diagram, orient="vertical", command=self.canvas.yview)
        xs = ttk.Scrollbar(diagram, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        self.canvas.bind("<Configure>", lambda _: self._draw())
        self.canvas.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(-int(e.delta / 120), "units"))
        ttk.Label(right, text="CHI TIẾT VÀ CĂN CỨ", foreground=colors["blue"],
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10, 6))
        detail = ttk.Frame(right)
        detail.pack(fill="x", padx=(10, 0))
        self.details = tk.Text(detail, height=7, wrap="word", state="disabled", font=("Segoe UI", 10),
                               bg=colors["panel"], fg=colors["text"], padx=12, pady=10, relief="flat")
        ds = ttk.Scrollbar(detail, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=ds.set)
        ds.pack(side="right", fill="y")
        self.details.pack(side="left", fill="both", expand=True)
        self.reload()

    def reload(self):
        try:
            data = json.loads(self.graph_path.read_text(encoding="utf-8"))
            nodes = {node["id"]: node for node in data["nodes"]}
            if not nodes or len(nodes) != len(data["nodes"]):
                raise ValueError("Graph rỗng hoặc trùng ID thực thể.")
            predicates = data["predicate_labels"]
            for edge in data["edges"]:
                if edge["source"] not in nodes or edge["target"] not in nodes or edge["predicate"] not in predicates:
                    raise ValueError("Graph có quan hệ không hợp lệ.")
            self.nodes, self.edges, self.predicates = nodes, data["edges"], predicates
            self.summary.set(f"{len(nodes)} thực thể • {len(self.edges)} quan hệ có hướng • "
                             f"Snapshot {data.get('snapshot_date', '')} • Kiến thức về tool, không phải dữ liệu một APK.")
            self._filter()
            self.show_entity(self.selected if self.selected in self.nodes else next(iter(nodes)))
        except (OSError, ValueError, KeyError, TypeError) as error:
            self.nodes, self.edges, self.predicates = {}, [], {}
            self.tree.delete(*self.tree.get_children())
            self.canvas.delete("all")
            self.summary.set(f"Không đọc được Knowledge Graph: {error}")
            self._set_details(f"Nguồn: {self.graph_path}\nDựng lại dữ liệu bằng: python scripts/build_knowledge_graph.py")

    def _filter(self, *_):
        self.tree.delete(*self.tree.get_children())
        query = self.search.get().strip().casefold()
        for id, node in sorted(self.nodes.items(), key=lambda item: item[1]["label"].casefold()):
            if not query or query in f"{id} {node['label']} {node['description']}".casefold():
                self.tree.insert("", "end", iid=id, text=node["label"])
        if self.tree.exists(self.selected):
            self.tree.selection_set(self.selected)

    def _tree_selected(self, _):
        selection = self.tree.selection()
        if selection and selection[0] != self.selected:
            self.show_entity(selection[0])

    def _set_details(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def show_entity(self, id):
        if id not in self.nodes:
            return
        self.selected = id
        node = self.nodes[id]
        lines = [f"{node['label']} — {TYPE_LABELS.get(node['type'], node['type'])}", node["description"], "", "Căn cứ:"]
        for ev in node.get("evidence", []):
            path = self.graph_path.parents[1] / ev["file"]
            lines.append(f"{path}:{ev['line']}" + (f" — {ev['symbol']}" if ev.get("symbol") else ""))
        lines += ["", "Các quan hệ:"]
        for edge in self.edges:
            if id in {edge["source"], edge["target"]}:
                lines.append(f"{self.nodes[edge['source']]['label']} → {self.predicates[edge['predicate']]} → "
                             f"{self.nodes[edge['target']]['label']}")
        self._set_details("\n".join(lines))
        if self.tree.exists(id):
            self.tree.selection_set(id)
            self.tree.see(id)
        self.canvas.yview_moveto(0)
        self.canvas.xview_moveto(0)
        self._draw()

    def _draw(self):
        self.canvas.delete("all")
        if self.selected not in self.nodes:
            return
        incoming = [e for e in self.edges if e["target"] == self.selected]
        outgoing = [e for e in self.edges if e["source"] == self.selected]
        width = max(740, self.canvas.winfo_width())
        box = (width - 150) / 3
        middle = (width - box) / 2
        last = width - box - 12
        height = max(250, 50 + max(len(incoming), len(outgoing)) * 110)
        cy = max(70, (min(height, max(250, self.canvas.winfo_height())) - 96) / 2)
        self.canvas.configure(scrollregion=(0, 0, width, height))
        for x, text in [(12, f"ĐI VÀO ({len(incoming)})"), (middle, "ĐANG CHỌN"), (last, f"ĐI RA ({len(outgoing)})")]:
            self.canvas.create_text(x, 12, text=text, anchor="nw", fill=self.colors["blue"], font=("Segoe UI", 9, "bold"))
        for index, edge in enumerate(incoming):
            y = 42 + index * 110
            self.canvas.create_line(12 + box, y + 48, middle, cy + 48,
                                    arrow="last", fill=self.colors["border"], width=2)
        for index, edge in enumerate(outgoing):
            y = 42 + index * 110
            self.canvas.create_line(middle + box, cy + 48, last, y + 48,
                                    arrow="last", fill=self.colors["border"], width=2)
        def draw_node(id, x, y, relation=None, active=False):
            node = self.nodes[id]
            tag = f"entity_{id}_{int(y)}_{int(x)}"
            self.canvas.create_rectangle(x, y, x + box, y + 96, fill=self.colors["selection"] if active else self.colors["surface"],
                                         outline=self.colors["blue"] if active else self.colors["border"], tags=tag)
            self.canvas.create_text(x + 9, y + 9, anchor="nw", text=node["label"], width=box - 18,
                                    fill=self.colors["text"], font=("Segoe UI", 10, "bold"), tags=tag)
            self.canvas.create_text(x + 9, y + 62, anchor="nw", text=relation or TYPE_LABELS.get(node["type"], node["type"]),
                                    width=box - 18, fill=self.colors["muted"], font=("Segoe UI", 9), tags=tag)
            self.canvas.tag_bind(tag, "<Button-1>", lambda _, target=id: self.show_entity(target))
            self.canvas.tag_bind(tag, "<Enter>", lambda _: self.canvas.configure(cursor="hand2"))
            self.canvas.tag_bind(tag, "<Leave>", lambda _: self.canvas.configure(cursor=""))
        for index, edge in enumerate(incoming):
            draw_node(edge["source"], 12, 42 + index * 110, self.predicates[edge["predicate"]])
        for index, edge in enumerate(outgoing):
            draw_node(edge["target"], last, 42 + index * 110, self.predicates[edge["predicate"]])
        draw_node(self.selected, middle, cy, active=True)
