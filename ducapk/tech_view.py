"""Tab "Công nghệ": engine, libraries, SDKs and shaders found in a job (tech_stack.json)."""
from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .tech_stack import GROUPS, scan_tech_stack

SHADER_GROUP = "Shader"
UNKNOWN_GROUP = "Thư viện chưa nhận diện"
FEATURE_GROUP = "Tính năng game ← material"
SCENE_GROUP = "Prefab & Scene"
SCRIPT_GROUP = "Script game gắn trên object"


class TechStackView(ttk.Frame):
    def __init__(self, parent, colors: dict, accent: str, get_job, set_job):
        super().__init__(parent)
        self.colors, self.accent = colors, accent
        self.get_job, self.set_job = get_job, set_job
        self.shown_job: Path | None = None
        self.data: dict | None = None
        self.details: dict[str, tuple[str, object]] = {}
        self.events: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.cancel = threading.Event()

        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 10))
        self.summary = tk.StringVar(value="Chưa mở job.")
        ttk.Label(top, textvariable=self.summary, font=("Segoe UI Semibold", 11),
                  foreground=accent).pack(side="left")
        self.scan_btn = ttk.Button(top, text="Quét lại", command=self.scan)
        self.scan_btn.pack(side="right")
        ttk.Button(top, text="Mở job", command=self._pick_job).pack(side="right", padx=(0, 8))
        self.status = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status, foreground=colors["muted"],
                  font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 6))

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left, right = ttk.Frame(panes), ttk.Frame(panes)
        panes.add(left, weight=2)
        panes.add(right, weight=3)
        self.tree = ttk.Treeview(left, columns=("info",), show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Công nghệ")
        self.tree.heading("info", text="Dùng để")
        self.tree.column("#0", width=360, stretch=True)
        self.tree.column("info", width=240, stretch=True)
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.tag_configure("group", foreground=accent, font=("Segoe UI Semibold", 10))
        self.tree.tag_configure("used", foreground=colors["text"])
        self.tree.tag_configure("idle", foreground=colors["muted"])
        self.tree.bind("<<TreeviewSelect>>", self._selected)

        self.text = tk.Text(right, wrap="word", bg=colors["panel"], fg=colors["text"], relief="flat",
                            borderwidth=0, padx=18, pady=14, font=("Segoe UI", 10), cursor="arrow",
                            spacing1=1, spacing3=3)
        text_scroll = ttk.Scrollbar(right, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=text_scroll.set)
        text_scroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True, padx=(10, 0))
        self.text.tag_configure("title", font=("Segoe UI", 15, "bold"), spacing3=4)
        self.text.tag_configure("muted", foreground=colors["muted"])
        self.text.tag_configure("h", font=("Segoe UI Semibold", 10), foreground=accent, spacing1=10)
        self.text.tag_configure("mono", font=("Consolas", 9))
        self.text.tag_configure("via", font=("Consolas", 9, "bold"), foreground=accent)
        self.text.tag_configure("chip", font=("Segoe UI Semibold", 9), foreground=colors["ink"],
                                background=accent)
        self._write([("Mở một job đã phân tích để xem game dùng công nghệ gì.", "muted")])
        self.after(150, self._pump)

    # ---------- dữ liệu ----------
    def refresh(self) -> None:
        """Show the current job; called when the tab is opened or a job is loaded."""
        job = self.get_job()
        if job is None or job == self.shown_job:
            return
        self.shown_job = job
        path = job / "tech_stack.json"
        if path.is_file():
            try:
                self._show(json.loads(path.read_text(encoding="utf-8")))
                return
            except (OSError, ValueError):
                pass
        self.data = None
        self.tree.delete(*self.tree.get_children())
        self.summary.set(job.name)
        if (job / "job.json").is_file():
            self.scan()
        else:
            self._write([("Thư mục này không phải job DucAPK.", "muted")])

    def scan(self) -> None:
        job = self.get_job()
        if job is None:
            messagebox.showinfo("Công nghệ", "Mở một job trước (nút Mở job).")
            return
        if self.worker and self.worker.is_alive():
            return
        self.scan_btn.configure(state="disabled")
        self.cancel.clear()
        self.status.set("Đang quét APK, assembly và shader...")

        def run():
            try:
                result = scan_tech_stack(job, lambda m: self.events.put(("log", m)), self.cancel)
                self.events.put(("done", job, result))
            except Exception as error:
                self.events.put(("error", str(error)))

        self.worker = threading.Thread(target=run, daemon=True)
        self.worker.start()

    def stop(self) -> None:
        self.cancel.set()

    def _pump(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "log":
                    self.status.set(event[1])
                elif event[0] == "done":
                    self.scan_btn.configure(state="normal")
                    if event[1] == self.get_job():
                        self.shown_job = event[1]
                        self._show(event[2])
                elif event[0] == "error":
                    self.scan_btn.configure(state="normal")
                    self.status.set("Lỗi: " + event[1])
        except queue.Empty:
            pass
        self.after(150, self._pump)

    def _pick_job(self):
        directory = filedialog.askdirectory(title="Chọn thư mục job DucAPK")
        if directory:
            self.set_job(Path(directory))
            self.shown_job = None
            self.refresh()

    # ---------- hiển thị ----------
    def _show(self, data: dict) -> None:
        self.data = data
        engine = data.get("engine", {})
        parts = [engine.get("name") or "?", engine.get("version"), engine.get("scripting_backend"),
                 engine.get("render_pipeline") and f"Render: {engine['render_pipeline']}"]
        self.summary.set("  ·  ".join(p for p in parts if p) +
                         f"   |   {len(data.get('technologies', []))} công nghệ/SDK, {len(data.get('shaders', []))} shader")
        self.status.set(f"{data.get('package') or ''}  —  bấm một mục để xem bằng chứng và class game dùng nó.")
        tree, self.details = self.tree, {}
        tree.delete(*tree.get_children())
        by_group: dict[str, list[dict]] = {}
        for tech in data.get("technologies", []):
            by_group.setdefault(tech["group"], []).append(tech)
        for group in GROUPS:
            items = by_group.get(group)
            if not items:
                continue
            node = tree.insert("", "end", text=f"{group}  ({len(items)})", tags=("group",), open=True)
            self.details[node] = ("group", (group, items))
            for tech in items:
                used = tech["usage_total"]
                label = tech["name"] + (f"   · {used} class game" if used else "")
                item = tree.insert(node, "end", text=label, values=(tech["purpose"],),
                                   tags=("used" if used or tech.get("shaders") else "idle",))
                self.details[item] = ("tech", tech)
        shaders = data.get("shaders", [])
        if shaders:
            node = tree.insert("", "end", text=f"{SHADER_GROUP}  ({len(shaders)})", tags=("group",), open=True)
            self.details[node] = ("group", (SHADER_GROUP, []))
            owners: dict[str, list[dict]] = {}
            for shader in shaders:
                owners.setdefault(shader["owner"], []).append(shader)
            order = sorted(owners, key=lambda o: (o != "Shader riêng của game", o == "Unity (có sẵn)", o))
            for owner in order:
                sub = tree.insert(node, "end", text=f"{owner}  ({len(owners[owner])})", tags=("group",),
                                  open=owner == "Shader riêng của game")
                self.details[sub] = ("group", (owner, []))
                for shader in owners[owner]:
                    item = tree.insert(sub, "end", text=shader["name"],
                                       values=(", ".join(shader["hints"][:2]),),
                                       tags=("used" if shader["material_count"] else "idle",))
                    self.details[item] = ("shader", shader)
        feature_rows = data.get("features", [])
        if feature_rows:
            node = tree.insert("", "end", text=f"{FEATURE_GROUP}  ({len(feature_rows)})", tags=("group",),
                               open=True)
            self.details[node] = ("group", (FEATURE_GROUP, []))
            kinds: dict[str, list[dict]] = {}
            for row in feature_rows:
                kinds.setdefault(row["kind"], []).append(row)
            for kind_name, rows in kinds.items():
                sub = tree.insert(node, "end", text=f"{kind_name}  ({len(rows)})", tags=("group",),
                                  open=kind_name == "Cơ chế level")
                self.details[sub] = ("group", (kind_name, []))
                for row in rows:
                    item = tree.insert(sub, "end", text=row["name"],
                                       values=(", ".join(row["materials"][:3]),), tags=("used",))
                    self.details[item] = ("feature", row)
        scenes = data.get("scenes", [])
        if scenes:
            node = tree.insert("", "end", text=f"{SCENE_GROUP}  ({len(scenes)})", tags=("group",))
            self.details[node] = ("group", (SCENE_GROUP, []))
            for scene in scenes:
                item = tree.insert(node, "end", text=scene["source"],
                                   values=(f"{scene['components']} component, {len(scene['materials'])} material",),
                                   tags=("used",))
                self.details[item] = ("scene", scene)
        components = data.get("game_components", [])
        if components:
            node = tree.insert("", "end", text=f"{SCRIPT_GROUP}  ({len(components)})", tags=("group",))
            self.details[node] = ("group", (SCRIPT_GROUP, []))
            for row in components:
                item = tree.insert(node, "end", text=row["script"], values=(f"{row['count']} object",),
                                   tags=("used",))
                self.details[item] = ("component", row)
        unknown = data.get("unrecognized_assemblies", [])
        if unknown:
            node = tree.insert("", "end", text=f"{UNKNOWN_GROUP}  ({len(unknown)})", tags=("group",))
            self.details[node] = ("unknown", unknown)
            for name in unknown:
                self.details[tree.insert(node, "end", text=name, tags=("idle",))] = ("unknown", unknown)
        self._overview()

    def _selected(self, _):
        selection = self.tree.selection()
        if not selection or selection[0] not in self.details:
            return
        kind, value = self.details[selection[0]]
        if kind == "tech":
            self._tech(value)
        elif kind == "shader":
            self._shader(value)
        elif kind == "scene":
            self._scene(value)
        elif kind == "component":
            self._component(value)
        elif kind == "feature":
            self._feature(value)
        elif kind == "unknown":
            self._write([(UNKNOWN_GROUP, "title"), ("\n", None),
                         ("Assembly C# không thuộc thư viện nào DucAPK biết; thường là framework riêng "
                          "của studio hoặc plugin ít phổ biến. Xem class bên trong ở tab Duyệt mã.\n", "muted"),
                         ("\n".join(value), "mono")])
        else:
            self._overview()

    def _overview(self):
        data = self.data or {}
        engine = data.get("engine", {})
        lines = [("Tổng quan", "title"), ("\n", None)]
        for key, label in (("name", "Engine"), ("version", "Phiên bản"), ("scripting_backend", "Biên dịch C#"),
                           ("render_pipeline", "Render pipeline")):
            if engine.get(key):
                lines += [(f"{label}: ", "h"), (f"{engine[key]}\n", None)]
        custom = [s for s in data.get("shaders", []) if s["owner"] == "Shader riêng của game"]
        if custom:
            lines += [("\nShader riêng của game\n", "h")]
            for shader in custom:
                lines += [(f"• {shader['name']}", None),
                          (f"  — {', '.join(shader['hints']) or 'chưa rõ công dụng'}\n", "muted")]
        used = sorted((t for t in data.get("technologies", []) if t["usage_total"]),
                      key=lambda t: -t["usage_total"])
        if used:
            lines += [("\nThư viện được code game dùng nhiều nhất\n", "h")]
            for tech in used[:15]:
                lines += [(f"• {tech['name']}", None), (f"  — {tech['usage_total']} class · {tech['purpose']}\n", "muted")]
        natives = data.get("native_libraries", [])
        if natives:
            lines += [("\nThư viện native (.so)\n", "h"), (", ".join(natives) + "\n", "mono")]
        self._write(lines)

    def _tech(self, tech: dict):
        lines = [(tech["name"], "title"), ("\n", None), (f"{tech['group']} · {tech['purpose']}\n", "muted"),
                 ("\nBằng chứng trong APK\n", "h")]
        lines += [(f"• {line}\n", None) for line in tech["evidence"]]
        if tech.get("shaders"):
            lines += self._tech_shader_lines(tech["shaders"])
        if tech.get("components"):
            lines += [("\nComponent gắn trên object (prefab/scene)\n", "h")]
            lines += self._component_lines(tech["components"])
        if tech["usage"]:
            lines += [(f"\nClass game dùng nó ({tech['usage_total']})\n", "h"),
                      ("Kiểu của thư viện xuất hiện trong field, class cha hoặc tham số/kết quả hàm "
                       "của các class này; mở tab Duyệt mã để xem pseudocode.\n", "muted")]
            for row in tech["usage"]:
                lines += [(f"• {row['class']}", None), (f"  →  {', '.join(row['types'])}\n", "mono")]
            if tech["usage_total"] > len(tech["usage"]):
                lines.append((f"... và {tech['usage_total'] - len(tech['usage'])} class khác\n", "muted"))
        elif tech.get("shaders") or tech.get("components"):
            lines += [("\nClass game dùng nó\n", "h"),
                      ("Code game không gọi trực tiếp thư viện này; nó được dùng qua material/prefab ở trên.\n",
                       "muted")]
        else:
            lines += [("\nClass game dùng nó\n", "h"),
                      ("Không thấy class game nào nhắc trực tiếp tới kiểu của thư viện này "
                       "(có thể được gọi qua SDK khác, qua prefab/Inspector, hoặc chỉ là phần Java).\n", "muted")]
        self._write(lines)

    def _shader(self, shader: dict):
        lines = [(shader["name"], "title"), ("\n", None), (f"Nguồn: {shader['owner']}\n", "muted")]
        if shader["hints"]:
            lines += [("\nCông dụng (đoán từ tên và thuộc tính)\n", "h")]
            lines += [(f"• {hint}\n", None) for hint in shader["hints"]]
        lines.append((f"\nMaterial dùng shader này và nơi gắn ({shader['material_count']})\n", "h"))
        if not shader["materials"]:
            lines.append(("Không có material nào trong APK gán shader này; thường được code tạo material "
                          "lúc chạy.\n", "muted"))
        uses = shader.get("material_uses", {})
        for material in shader["materials"]:
            entry = uses.get(material, {"count": 0, "uses": []})
            lines.append((f"• {material}", None))
            lines += self._purpose_line(entry)
            if not entry["uses"]:
                lines.append(("  — không thấy object/script nào gắn trực tiếp (có thể code nạp hoặc gán lúc chạy, "
                              "hoặc nằm trong script đã bị bỏ typetree khi build)\n", "muted"))
                continue
            lines.append((f"  — {entry['count']} chỗ gắn\n", "muted"))
            for use in entry["uses"]:
                lines += self._use_lines(use)
            if entry["count"] > len(entry["uses"]):
                lines.append((f"      ... và {entry['count'] - len(entry['uses'])} chỗ khác\n", "muted"))
        if shader["properties"]:
            lines += [("\nThuộc tính (properties)\n", "h"), (", ".join(shader["properties"]) + "\n", "mono")]
        if shader["files"]:
            lines += [("\nNằm trong\n", "h"), ("\n".join(shader["files"]) + "\n", "mono")]
        self._write(lines)

    def _tech_shader_lines(self, names: list[str]) -> list[tuple[str, str | None]]:
        """Each shader of a library, its materials and where they are attached."""
        by_name = {shader["name"]: shader for shader in (self.data or {}).get("shaders", [])}
        lines = [("\nShader của thư viện này và nơi được dùng\n", "h")]
        for name in names:
            shader = by_name.get(name, {})
            uses = shader.get("material_uses", {})
            materials = shader.get("materials", [])
            sources = {use["source"] for entry in uses.values() for use in entry["uses"]}
            attached = sum(entry["count"] for entry in uses.values())
            lines += [(f"{name}\n", "mono"),
                      (f"   {shader.get('material_count', 0)} material, {attached} chỗ gắn"
                       + (f" trong {len(sources)} prefab/scene" if sources else "") + "\n", "muted")]
            shown = sorted(materials, key=lambda m: -uses.get(m, {}).get("count", 0))
            for material in shown[:10]:
                entry = uses.get(material, {"count": 0, "uses": []})
                lines.append((f"• {material}", None))
                lines += self._purpose_line(entry)
                if not entry["uses"]:
                    lines.append(("  — không thấy chỗ gắn trực tiếp\n", "muted"))
                    continue
                lines.append((f"  — {entry['count']} chỗ gắn\n", "muted"))
                for use in entry["uses"][:3]:
                    lines += self._use_lines(use)
            if len(shown) > 10:
                lines.append((f"   ... và {len(shown) - 10} material khác; bấm shader trong nhóm Shader để xem hết\n",
                              "muted"))
        return lines

    @staticmethod
    def _purpose_line(entry: dict) -> list[tuple[str, str | None]]:
        purpose = entry.get("purpose") or {}
        if not purpose.get("summary"):
            return []
        prefix = "  ⇒ đoán theo tên: " if purpose.get("guessed") else "  ⇒ phục vụ: "
        return [(prefix, "via"), (purpose["summary"], None)]

    def _feature(self, feature: dict):
        lines = [(feature["name"], "title"), ("\n", None), (f"{feature['kind']}\n", "muted")]
        if feature["kind"] == "Cơ chế level":
            lines.append(("Field/enum trong LevelModel.cs; khớp vì tên object hoặc material chứa cùng từ "
                          "(ví dụ Gun/.../Ice/... ↔ GunData.IceHp). Đây là gợi ý theo tên.\n", "muted"))
        lines += [(f"\nMaterial phục vụ ({len(feature['materials'])})\n", "h"),
                  ("\n".join(feature["materials"]) + "\n", "mono")]
        if feature["sources"]:
            lines += [("\nNằm trong prefab/scene\n", "h"), ("\n".join(feature["sources"]) + "\n", "mono")]
        if feature["objects"]:
            lines += [("\nObject mẫu\n", "h"), ("\n".join(feature["objects"]) + "\n", "mono")]
        self._write(lines)

    @staticmethod
    def _use_lines(use: dict) -> list[tuple[str, str | None]]:
        lines = [(f"      {use['via'] or 'tham chiếu'}  ", "via"), (f"{use['object']}\n", "mono"),
                 (f"         trong {use['source']}\n", "muted")]
        if use.get("scripts"):
            names = ", ".join(script.rsplit(".", 1)[-1] for script in use["scripts"])
            lines.append((f"         script cùng object: {names}\n", "muted"))
        return lines

    @staticmethod
    def _component_lines(rows: list[dict]) -> list[tuple[str, str | None]]:
        lines = []
        for row in rows:
            lines += [(f"• {row['script']}", None), (f"  — gắn trên {row['count']} object\n", "muted")]
            for place in row["objects"]:
                lines += [(f"      {place['object']}\n", "mono"), (f"         trong {place['source']}\n", "muted")]
        return lines

    def _scene(self, scene: dict):
        lines = [(scene["source"], "title"), ("\n", None),
                 (f"{scene['components']} component script trong prefab/scene này\n", "muted"),
                 ("\nScript gắn trên object (số lần)\n", "h")]
        for name, count in scene["scripts"]:
            lines += [(f"• {name}", None), (f"  × {count}\n", "muted")]
        if scene["materials"]:
            lines += [("\nMaterial dùng trong này\n", "h"), ("\n".join(scene["materials"]) + "\n", "mono")]
        self._write(lines)

    def _component(self, row: dict):
        lines = [(row["script"], "title"), ("\n", None),
                 (f"Script của game, gắn trên {row['count']} object. Mở class này ở tab Duyệt mã để xem code.\n",
                  "muted"), ("\nMột số object có script này\n", "h")]
        for place in row["objects"]:
            lines += [(f"• {place['object']}\n", "mono"), (f"     trong {place['source']}\n", "muted")]
        self._write(lines)

    def _write(self, parts: list[tuple[str, str | None]]):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        for text, tag in parts:
            self.text.insert("end", text, (tag,) if tag else ())
        self.text.configure(state="disabled")
        self.text.yview_moveto(0)
