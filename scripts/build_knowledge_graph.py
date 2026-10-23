"""Build the curated DucAPK knowledge graph with source evidence.

This is an architecture/capability snapshot, not a graph of a particular APK.
Re-run after reviewing the curated facts when implementation changes.
"""
from pathlib import Path
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "knowledge"
nodes, edges = [], []


def evidence(path, symbol=None):
    text = (ROOT / path).read_text(encoding="utf-8-sig")
    line = 1
    if symbol and path.endswith(".py"):
        matches = [n for n in ast.walk(ast.parse(text))
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == symbol]
        if not matches:
            raise ValueError(f"Missing source symbol: {path}:{symbol}")
        line = matches[0].lineno
    return {"file": path, "line": line, "symbol": symbol}


def node(id, label, type, description, path, symbol=None, **properties):
    nodes.append(dict(id=id, label=label, type=type, description=description,
                      properties=properties, evidence=[evidence(path, symbol)]))


def edge(source, predicate, target, path, symbol=None, note=""):
    edges.append(dict(id=f"r{len(edges)+1:03}", source=source, predicate=predicate,
                      target=target, note=note, evidence=[evidence(path, symbol)]))


node("ducapk", "DucAPK", "application", "Công cụ Windows phân tích APK Android, trích metadata/level và chuyển mã tham chiếu C#.", "README.md")
for id, label, desc, path in [
    ("gui", "Giao diện desktop", "TkinterDnD; bốn tab Phân tích, Duyệt mã, API dịch mã, Kho tri thức; worker nền và hàng đợi sự kiện.", "app.py"),
    ("cli", "Command line", "Nhận APK hoặc --resume; chọn nhóm, metadata-only và bật/tắt trích level. CLI hiện chưa có lệnh dịch API.", "cli.py"),
    ("runner", "Điều phối phân tích", "Tạo/tiếp tục job, chọn parser, chạy decompiler và tổng hợp kết quả.", "ducapk/runner.py"),
    ("archive", "Đọc gói APK", "Bung container/split, chọn cặp native binary và metadata; ưu tiên arm64-v8a.", "ducapk/archive.py"),
    ("metadata", "Lập chỉ mục metadata", "Đối chiếu class, method, signature, RVA; giữ cả khai báo không có địa chỉ native.", "ducapk/metadata.py"),
    ("categories", "Phân nhóm class", "Phân loại theo namespace; namespace không nhận diện thuộc nhóm game.", "ducapk/categories.py"),
    ("levels", "Trích dữ liệu level", "Đọc bundles/TextAsset, các codec và schema được hỗ trợ; làm giàu mechanic bằng enum metadata.", "ducapk/levels.py"),
    ("offline", "Dịch C → C# offline", "Chuyển các mẫu pseudocode phổ biến sang unsafe C# tham chiếu và ghi cảnh báo phần chưa liên kết.", "ducapk/csharp_export.py"),
    ("api", "Dịch mã bằng API", "Dịch C sang C# hoặc hoàn thiện C# decompile qua Chat Completions tương thích OpenAI.", "ducapk/api_translation.py"),
]:
    node(id, label, "interface" if id in {"gui", "cli"} else "module", desc, path)
    edge("ducapk", "has_interface" if id in {"gui", "cli"} else "has_module", id, path)

for id, label, desc, path, symbol in [
    ("analyze", "Phân tích APK", "Điều phối luồng IL2CPP/DEX; có thể lấy thêm Java ở job Unity.", "ducapk/runner.py", "analyze"),
    ("browse", "Duyệt class / method", "Đọc SQLite, tìm class và hiển thị chữ ký/RVA/trạng thái/pseudocode.", "app.py", "_method_selected"),
    ("resume", "Tiếp tục job", "Đọc cấu hình và đầu vào job cũ, giữ nhóm đã chọn, tận dụng kết quả đã có.", "ducapk/runner.py", "analyze"),
    ("retry", "Thử lại hàm lỗi", "Chỉ chạy lại hàm native thiếu thân; các timeout thử lại là 120 và 180 giây.", "ducapk/runner.py", "retry_failed_only"),
    ("recover", "Khôi phục XOR metadata đã biết", "Hỗ trợ wrapper có khóa cố định được đánh dấu trong libil2cpp.so và biến thể Il2cppEncrtypt có khóa DWORD nhúng (kl 130–140); xác thực header/nội dung, ghi sidecar và giữ metadata gốc.", "ducapk/runner.py", "_metadata_path"),
    ("scope", "Chọn phạm vi decompile", "Lập danh sách native method theo nhóm mà vẫn giữ metadata đầy đủ. Mặc định nhóm game.", "ducapk/runner.py", "_build_scope_manifest"),
    ("batch", "Lưu native theo lô", "Ghidra xuất lô tối đa 1.000 phương thức; Python nhập kết quả và gom file theo class.", "ducapk/runner.py", "_run_ghidra"),
    ("enum", "Ánh xạ mechanic từ enum", "Đối chiếu ID có ngữ nghĩa với enum metadata của APK; giữ ID gốc, không đoán khi thiếu/mơ hồ.", "ducapk/levels.py", "annotate_level_mechanics"),
    ("api_test", "Kiểm tra API / model", "Gửi yêu cầu thử nhỏ, kiểm tra model trả nội dung; yêu cầu có thể tính phí.", "ducapk/api_translation.py", "test_connection"),
    ("api_export", "Dịch lô C / C# qua API", "Đọc một file hoặc cây thư mục; từng file được xử lý độc lập, lưu cây kết quả riêng và báo cáo.", "ducapk/api_translation.py", "export_api"),
]:
    node(id, label, "capability", desc, path, symbol)

for id, label, desc, path, symbol in [
    ("packages", "APK / XAPK / APKS / split", "Các split phải cùng bản game; ZIP container và đầu vào binary/metadata rời cũng được đọc.", "ducapk/archive.py", "extract_il2cpp_pair"),
    ("binary", "libil2cpp.so", "Native binary chứa code IL2CPP; cần ghép với metadata của cùng bản.", "ducapk/archive.py", "extract_il2cpp_pair"),
    ("metadata_dat", "global-metadata.dat", "Tên class/method, chữ ký và metadata IL2CPP; parser cần đọc được định dạng.", "ducapk/runner.py", "_run_dumper"),
    ("dex", "DEX Android", "Bytecode Java/Kotlin trong APK; có thể tồn tại cùng IL2CPP.", "ducapk/runner.py", "_run_jadx"),
    ("bundles", "Unity bundles / TextAsset", "Asset/config trong gói; bundle mã hóa riêng cần codec tương ứng.", "ducapk/levels.py", "_bundle_asset_index"),
    ("c_input", "File C / pseudocode", "File .c UTF-8, có thể chứa pseudocode Ghidra, metadata comments và RVA.", "ducapk/api_translation.py", "translate_file"),
    ("cs_input", "File C# decompile", "File .cs UTF-8 được dùng làm đầu vào hoàn thiện cú pháp/khả năng đọc.", "ducapk/api_translation.py", "translate_file"),
]:
    node(id, label, "input", desc, path, symbol)

node("il2cpp_core_workflow", "Quy trình lõi Unity IL2CPP",
     "capability",
     "Tri thức vận hành được job áp dụng: ghép libil2cpp.so với global-metadata.dat; chọn Il2CppDumper hoặc Cpp2IL theo phiên bản/kết quả parser; dùng Ghidra headless tạo pseudocode native từ RVA. Metadata/pseudocode không phải source C# gốc; metadata mã hóa tùy biến cần codec/khóa riêng.",
     "ducapk/runner.py", "analyze")
node("ghidra_csharp_knowledge", "Tri thức dịch pseudocode IL2CPP sang C#",
     "concept",
     "Prompt đang được áp dụng khi dịch file .c qua API: xem C là pseudocode native, giữ class/method/RVA, bảo toàn luồng điều khiển và phép toán có bằng chứng, giữ truy cập pointer/offset tường minh, không đoán gameplay/layout; vùng thiếu được ghi TODO/stub. Khuyến nghị kiểm tra bằng Roslyn nhưng tool chưa tự chạy compiler.",
     "ducapk/api_translation.py", "translate_file")

for id, label, desc, path, symbol in [
    ("dumper", "Il2CppDumper", "Parser IL2CPP lấy script.json và dump.cs; khi không phù hợp có thể chuyển Cpp2IL.", "ducapk/runner.py", "_run_dumper"),
    ("cpp2il", "Cpp2IL", "Parser/ánh xạ thay thế; cần xác định phiên bản Unity và dùng .NET riêng của tool.", "ducapk/runner.py", "_run_cpp2il"),
    ("ghidra", "Ghidra headless", "Decompiler native được gọi qua analyzeHeadless; tạo pseudocode từ địa chỉ đã lập chỉ mục.", "ducapk/runner.py", "_headless"),
    ("ghidra_script", "DucAPKDecompile.java", "Script Ghidra đọc method manifest và xuất kết quả/trạng thái; tận dụng lô đã xử lý.", "scripts/DucAPKDecompile.java", None),
    ("jadx", "JADX", "Decompiler DEX sang Java; fallback không thay thế phần IL2CPP bị lỗi.", "ducapk/runner.py", "_run_jadx"),
    ("unitypy", "UnityPy", "Đọc Unity assets và bundles để lấy TextAsset và dữ liệu object.", "ducapk/levels.py", "_bundle_asset_index"),
    ("crypto", "PyCryptodome", "Giải mã AES-CBC cho PackageManifest YooAsset theo định dạng được hỗ trợ.", "ducapk/levels.py", "_decrypt_package_manifest"),
    ("dotnet", ".NET runtime riêng", "tools/dotnet/dotnet.exe chạy Cpp2IL.", "ducapk/runner.py", "_run_cpp2il"),
    ("llm", "API model bên ngoài / local", "POST Chat Completions với model, messages, stream=false; dùng Base URL do người dùng nhập.", "ducapk/api_translation.py", "complete"),
]:
    node(id, label, "dependency", desc, path, symbol)

for id, label, desc, path, symbol in [
    ("job", "Job / job.json", "Một phiên phân tích: đầu vào, lựa chọn nhóm, backend, trạng thái và báo cáo; dùng cho resume.", "ducapk/runner.py", "_state"),
    ("sqlite", "methods.sqlite", "Các bảng methods, selected_methods, results liên kết metadata, phạm vi và pseudocode/trạng thái.", "ducapk/runner.py", "_collect_results"),
    ("class_index", "class_index.csv", "Mục lục class tạo từ metadata.", "ducapk/metadata.py", "build_metadata_index"),
    ("class_meta", "classes_metadata/", "Khai báo class/method/signature/RVA; method không ánh xạ được vẫn được giữ.", "ducapk/metadata.py", "build_metadata_index"),
    ("manifest", "methods.tsv / selected.tsv", "Danh sách method và phạm vi native cần Ghidra xử lý.", "ducapk/runner.py", "_build_scope_manifest"),
    ("c_output", "classes_c/", "Pseudocode chia thành game_logic, unity_dotnet và third_party_sdk.", "ducapk/runner.py", "_collect_results"),
    ("dump", "dump.cs / method map", "dump.cs là khai báo metadata; Cpp2IL cung cấp bảng ánh xạ method thay thế.", "ducapk/runner.py", "_run_dumper"),
    ("java_output", "java_source/sources/", "Mã Java decompile từ DEX qua JADX.", "ducapk/runner.py", "_run_jadx"),
    ("level_output", "levels/ + levels.json", "JSON từng level và manifest nguồn/lỗi/bundle/pack/mechanic.", "ducapk/levels.py", "extract_level_json"),
    ("analysis_report", "report.json / failed_functions.json", "Số hàm có/thiếu thân, lỗi decompile và thông tin cần retry.", "ducapk/runner.py", "_collect_results"),
    ("log", "activity.log", "Nhật ký phân tích và tiến độ theo thời gian.", "ducapk/runner.py", "_job_logger"),
    ("project", "DucAPK.gpr", "Project Ghidra riêng dưới projects/job_<mã>/.", "ducapk/runner.py", "_project_dir"),
    ("offline_output", "C# offline + report", "Cây .cs tham chiếu và translation_report.json ghi stub/cảnh báo.", "ducapk/csharp_export.py", "export_c_tree"),
    ("api_output", "C# API + report", "Cây .cs riêng và api_translation_report.json; status needs_review, compiled=false.", "ducapk/api_translation.py", "export_api"),
]:
    node(id, label, "artifact", desc, path, symbol)

for id, label, desc, path, symbol in [
    ("game", "Logic game", "Nhóm mặc định; namespace chưa được nhận diện cũng thuộc nhóm này.", "ducapk/categories.py", "category_for_class"),
    ("unity", "Unity / .NET", "Nhóm class framework được phân loại theo namespace.", "ducapk/categories.py", "category_for_class"),
    ("sdk", "SDK bên thứ ba", "Nhóm SDK/thư viện được nhận diện theo các prefix đã cấu hình.", "ducapk/categories.py", "category_for_class"),
    ("hdpk", "Codec HDPK", "Đọc bảng offset và xuất bản ghi JSON level theo schema đã hỗ trợ.", "ducapk/levels.py", "_unpack_hdpk_pack"),
    ("msgpack", "Codec MessagePack puzzle", "Bộ unpack và nhận diện cấu trúc puzzle được hỗ trợ.", "ducapk/levels.py", "_unpack_msgpack"),
    ("juicetime", "Schema JuiceTime", "Nhận diện và bung payload level thành nhóm/xiên/màu/trạng thái; giữ chuỗi thô.", "ducapk/levels.py", "_parse_juicetime_level_payload"),
    ("yooasset", "PackageManifest / BundleStream", "Ánh xạ tên bundle, giải mã manifest và đảo biến đổi bundle theo format đã biết.", "ducapk/levels.py", "_decrypt_bundle_stream"),
]:
    node(id, label, "concept", desc, path, symbol)

for id, label, desc, path, symbol in [
    ("review", "C# cần rà soát / compile", "Pseudocode và C# tái dựng không được bảo đảm là source gốc hay tương đương; có TODO/stub.", "README.md", None),
    ("local", "Phân tích chạy local", "Phân tích và dịch offline chạy trên máy; tool không tự tải APK lên API.", "README.md", None),
    ("api_boundary", "Gửi file khi bấm dịch API", "Chỉ gửi nội dung file C/C# đã chọn; có thể tính phí, xử lý độc lập mỗi file, tối đa 240.000 byte UTF-8.", "ducapk/api_translation.py", "translate_file"),
    ("api_key", "API Key trong phiên", "Key được che; có thể đọc DUCAPK_API_KEY, không ghi trong báo cáo; không chuyển tiếp credential qua redirect.", "app.py", "_build_api_ui"),
    ("api_safety", "Kiểm tra phản hồi API", "Từ chối đầu ra bị cắt/chặn/sai định dạng; dừng lô khi lỗi kết nối/key/quota; HTTPS từ xa, HTTP localhost.", "ducapk/api_translation.py", "complete"),
    ("limits", "Giới hạn parser / codec", "Không có bộ giải mã chung cho mọi APK/metadata/bundle; tên đã obfuscate và logic thiếu không tự khôi phục.", "README.md", None),
]:
    node(id, label, "constraint", desc, path, symbol)

node("knowledge_view", "Trình xem Knowledge Graph", "module", "Tab desktop native: tìm thực thể, chọn nút lân cận, xem quan hệ có hướng và căn cứ source; đọc JSON local.", "ducapk/knowledge_view.py", "KnowledgeGraphView")
node("explore_graph", "Khám phá tri thức tool", "capability", "Chọn thực thể trong danh sách hoặc graph, xem quan hệ đi vào/đi ra, mô tả và file/dòng căn cứ; tải lại dữ liệu.", "ducapk/knowledge_view.py", "show_entity")
node("ghidra_source_view", "Tra cứu source Ghidra", "module", "Giao diện tìm source Ghidra đã đồng bộ, hiển thị đường dẫn, dòng và đoạn mã khớp.", "ducapk/ghidra_knowledge.py", "GhidraSourceView")
node("sync_ghidra_source", "Cập nhật kiến thức Ghidra", "capability", "Đồng bộ sparse checkout các module source chính thức từ GitHub và dựng lại chỉ mục SQLite FTS5 trong worker nền.", "ducapk/ghidra_knowledge.py", "update_ghidra_knowledge")
node("search_ghidra_source", "Tìm trong source Ghidra", "capability", "Tìm từ khóa trong source đã lập chỉ mục và trả về file, dòng cùng đoạn trích.", "ducapk/ghidra_knowledge.py", "search_ghidra_source")
node("graph_data", "Knowledge Graph JSON", "artifact", "knowledge/ducapk_knowledge_graph.json: thực thể, quan hệ có hướng, nhãn quan hệ, evidence và SHA-256 của source; snapshot biên tập về tool.", "scripts/build_knowledge_graph.py")
node("graph_builder", "Dựng snapshot tri thức", "module", "Script biên tập facts, lấy dòng symbol bằng AST, kiểm tra ID/quan hệ và xuất graph JSON cùng bảng Markdown; cần rà facts khi source đổi.", "scripts/build_knowledge_graph.py")
node("ghidra_source_checkout", "Checkout source Ghidra", "artifact", "knowledge/ghidra_upstream/: shallow/sparse checkout của repo chính thức, giới hạn vào các module được chọn.", "ducapk/ghidra_knowledge.py", "update_ghidra_knowledge")
node("ghidra_source_index", "Chỉ mục source Ghidra", "artifact", "knowledge/ghidra_source_index.sqlite3: nội dung source văn bản và metadata commit dùng cho truy vấn FTS5.", "ducapk/ghidra_knowledge.py", "_create_index")

relations = [
    ("ducapk", "has_module", "knowledge_view"), ("ducapk", "has_module", "graph_builder"),
    ("ducapk", "has_module", "ghidra_source_view"),
    ("gui", "exposes", "explore_graph"), ("knowledge_view", "implements", "explore_graph"),
    ("knowledge_view", "consumes", "graph_data"), ("explore_graph", "consumes", "graph_data"),
    ("graph_builder", "produces", "graph_data"),
    ("gui", "exposes", "sync_ghidra_source"), ("gui", "exposes", "search_ghidra_source"),
    ("ghidra_source_view", "implements", "sync_ghidra_source"),
    ("ghidra_source_view", "implements", "search_ghidra_source"),
    ("sync_ghidra_source", "updates", "ghidra_source_checkout"),
    ("sync_ghidra_source", "produces", "ghidra_source_index"),
    ("search_ghidra_source", "consumes", "ghidra_source_index"),
    ("gui", "invokes", "analyze"), ("cli", "invokes", "analyze"),
    ("gui", "exposes", "browse"), ("gui", "exposes", "api"), ("gui", "exposes", "offline"),
    ("gui", "exposes", "resume"), ("cli", "exposes", "resume"), ("gui", "exposes", "retry"),
    ("runner", "implements", "analyze"), ("runner", "implements", "resume"),
    ("runner", "implements", "retry"), ("runner", "implements", "recover"),
    ("runner", "implements", "scope"), ("runner", "implements", "batch"),
    ("analyze", "uses", "il2cpp_core_workflow"),
    ("il2cpp_core_workflow", "invokes", "dumper"),
    ("il2cpp_core_workflow", "fallback_to", "cpp2il"),
    ("il2cpp_core_workflow", "invokes", "ghidra"),
    ("analyze", "invokes", "archive"), ("analyze", "invokes", "metadata"),
    ("analyze", "invokes", "levels"), ("analyze", "invokes", "scope"),
    ("analyze", "invokes", "batch"), ("analyze", "invokes", "retry"),
    ("archive", "consumes", "packages"), ("archive", "extracts", "binary"), ("archive", "extracts", "metadata_dat"),
    ("runner", "invokes", "dumper"), ("runner", "invokes", "cpp2il"), ("runner", "invokes", "jadx"),
    ("dumper", "fallback_to", "cpp2il"), ("cpp2il", "uses", "dotnet"),
    ("dumper", "consumes", "binary"), ("dumper", "consumes", "metadata_dat"),
    ("cpp2il", "consumes", "binary"), ("cpp2il", "consumes", "metadata_dat"),
    ("dumper", "produces", "dump"), ("cpp2il", "produces", "dump"),
    ("recover", "consumes", "metadata_dat"), ("recover", "uses", "binary"),
    ("metadata", "consumes", "dump"), ("metadata", "produces", "sqlite"),
    ("metadata", "produces", "class_meta"), ("metadata", "produces", "class_index"),
    ("metadata", "produces", "manifest"), ("scope", "uses", "categories"),
    ("scope", "consumes", "manifest"), ("scope", "updates", "sqlite"),
    ("categories", "classifies", "game"), ("categories", "classifies", "unity"), ("categories", "classifies", "sdk"),
    ("batch", "invokes", "ghidra"), ("ghidra", "runs", "ghidra_script"),
    ("ghidra_script", "consumes", "manifest"), ("ghidra", "consumes", "binary"),
    ("batch", "updates", "sqlite"), ("runner", "produces", "c_output"),
    ("ghidra", "produces", "project"), ("runner", "produces", "analysis_report"),
    ("runner", "produces", "job"), ("runner", "produces", "log"),
    ("resume", "consumes", "job"), ("retry", "consumes", "sqlite"),
    ("retry", "invokes", "ghidra"), ("retry", "updates", "c_output"),
    ("retry", "updates", "analysis_report"), ("browse", "consumes", "sqlite"),
    ("jadx", "consumes", "dex"), ("jadx", "produces", "java_output"),
    ("levels", "consumes", "packages"), ("levels", "consumes", "bundles"),
    ("levels", "uses", "unitypy"), ("levels", "uses", "crypto"),
    ("levels", "supports", "hdpk"), ("levels", "supports", "msgpack"),
    ("levels", "supports", "juicetime"), ("levels", "supports", "yooasset"),
    ("levels", "implements", "enum"), ("enum", "consumes", "dump"),
    ("enum", "enriches", "level_output"), ("levels", "produces", "level_output"),
    ("offline", "consumes", "c_input"), ("offline", "consumes", "c_output"),
    ("offline", "produces", "offline_output"),
    ("api", "implements", "api_test"), ("api", "implements", "api_export"),
    ("api_test", "invokes", "llm"), ("api_export", "invokes", "llm"),
    ("api_export", "uses", "ghidra_csharp_knowledge"),
    ("api_export", "consumes", "c_input"), ("api_export", "consumes", "cs_input"),
    ("api_export", "consumes", "c_output"), ("api_export", "produces", "api_output"),
    ("api", "constrained_by", "api_boundary"), ("api", "constrained_by", "api_key"),
    ("api", "constrained_by", "api_safety"), ("api_output", "requires", "review"),
    ("offline_output", "requires", "review"), ("c_output", "requires", "review"),
    ("ducapk", "constrained_by", "limits"), ("analyze", "constrained_by", "local"),
    ("offline", "constrained_by", "local"),
]
by_id = {n['id']: n for n in nodes}
for source, predicate, target in relations:
    ev = by_id[source]['evidence'][0]
    # Process relationships take their evidence from the process implementation.
    if source == 'gui':
        ev = evidence('app.py', '_build_ui')
    elif source == 'cli':
        ev = evidence('cli.py', 'main')
    edge(source, predicate, target, ev['file'], ev['symbol'])

PREDICATES = {
    'has_interface': 'có giao diện', 'has_module': 'có module', 'invokes': 'gọi',
    'exposes': 'cung cấp', 'implements': 'triển khai', 'consumes': 'đọc đầu vào',
    'extracts': 'trích xuất', 'uses': 'sử dụng', 'produces': 'tạo ra',
    'fallback_to': 'chuyển sang khi không phù hợp', 'updates': 'cập nhật',
    'classifies': 'phân nhóm', 'runs': 'chạy script', 'supports': 'hỗ trợ định dạng',
    'enriches': 'làm giàu dữ liệu', 'constrained_by': 'chịu giới hạn', 'requires': 'cần',
}
assert len(by_id) == len(nodes)
assert all(e['source'] in by_id and e['target'] in by_id and e['predicate'] in PREDICATES for e in edges)
assert len({(e['source'], e['predicate'], e['target']) for e in edges}) == len(edges)
files = sorted({ev['file'] for item in nodes + edges for ev in item['evidence']})
graph = {'schema_version': '1.0', 'title': 'DucAPK Knowledge Graph',
         'snapshot_date': '2026-10-16', 'scope': 'Architecture, capabilities, inputs, outputs and constraints of the current source tree; excludes APK-specific recovered data.',
         'curation': 'Source-backed curated facts; updating the builder timestamp alone does not refresh facts.',
         'verification': 'Source inspection only; does not certify live external tool or API availability.',
         'directed': True, 'predicate_labels': PREDICATES,
         'sources': [{'file': f, 'sha256': hashlib.sha256((ROOT / f).read_bytes()).hexdigest()} for f in files],
         'nodes': nodes, 'edges': edges}
OUT.mkdir(exist_ok=True)
(OUT / 'ducapk_knowledge_graph.json').write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding='utf-8')
lines = ['# DucAPK Knowledge Graph', '', f"Snapshot 2026-10-16: {len(nodes)} thực thể, {len(edges)} quan hệ có hướng.", '',
         'Graph mô tả kiến trúc/chức năng hiện có của tool; không chứa class hay level của một APK cụ thể.', '',
         '## Cấu trúc dữ liệu', '',
         '`nodes`: id, label, type, description, properties, evidence.',
         '`edges`: id, source, predicate, target, note, evidence.',
         '`evidence`: file tương đối trong repo, số dòng, symbol nếu có.',
         '`sources`: SHA-256 của các file làm căn cứ cho snapshot.', '',
         'Loại thực thể: application, interface, module, capability, input, dependency, artifact, concept, constraint.', '',
         'Kiểm chứng: đọc source; chưa xác nhận khả năng chạy của API/tool bên ngoài trong snapshot.', '',
         '## Thực thể', '', '| ID | Thực thể | Loại | Mô tả |', '|---|---|---|---|']
for n in nodes:
    lines.append(f"| {n['id']} | {n['label']} | {n['type']} | {n['description']} |")
lines += ['', '## Các bộ ba quan hệ', '', '| Chủ thể | Quan hệ | Đối tượng | Căn cứ |', '|---|---|---|---|']
for e in edges:
    ev = e['evidence'][0]
    lines.append(f"| {by_id[e['source']]['label']} | {PREDICATES[e['predicate']]} | {by_id[e['target']]['label']} | {ev['file']}:{ev['line']} |")
lines += ['', 'Để dựng lại: `python scripts/build_knowledge_graph.py`. Các facts được biên tập trong script; cần rà lại khi source đổi.']
(OUT / 'ducapk_knowledge_graph.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(f"Built {len(nodes)} nodes / {len(edges)} directed edges in {OUT}")
