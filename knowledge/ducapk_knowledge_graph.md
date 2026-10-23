# DucAPK Knowledge Graph

Snapshot 2026-10-16: 74 thực thể, 126 quan hệ có hướng.

Graph mô tả kiến trúc/chức năng hiện có của tool; không chứa class hay level của một APK cụ thể.

## Cấu trúc dữ liệu

`nodes`: id, label, type, description, properties, evidence.
`edges`: id, source, predicate, target, note, evidence.
`evidence`: file tương đối trong repo, số dòng, symbol nếu có.
`sources`: SHA-256 của các file làm căn cứ cho snapshot.

Loại thực thể: application, interface, module, capability, input, dependency, artifact, concept, constraint.

Kiểm chứng: đọc source; chưa xác nhận khả năng chạy của API/tool bên ngoài trong snapshot.

## Thực thể

| ID | Thực thể | Loại | Mô tả |
|---|---|---|---|
| ducapk | DucAPK | application | Công cụ Windows phân tích APK Android, trích metadata/level và chuyển mã tham chiếu C#. |
| gui | Giao diện desktop | interface | TkinterDnD; bốn tab Phân tích, Duyệt mã, API dịch mã, Kho tri thức; worker nền và hàng đợi sự kiện. |
| cli | Command line | interface | Nhận APK hoặc --resume; chọn nhóm, metadata-only và bật/tắt trích level. CLI hiện chưa có lệnh dịch API. |
| runner | Điều phối phân tích | module | Tạo/tiếp tục job, chọn parser, chạy decompiler và tổng hợp kết quả. |
| archive | Đọc gói APK | module | Bung container/split, chọn cặp native binary và metadata; ưu tiên arm64-v8a. |
| metadata | Lập chỉ mục metadata | module | Đối chiếu class, method, signature, RVA; giữ cả khai báo không có địa chỉ native. |
| categories | Phân nhóm class | module | Phân loại theo namespace; namespace không nhận diện thuộc nhóm game. |
| levels | Trích dữ liệu level | module | Đọc bundles/TextAsset, các codec và schema được hỗ trợ; làm giàu mechanic bằng enum metadata. |
| offline | Dịch C → C# offline | module | Chuyển các mẫu pseudocode phổ biến sang unsafe C# tham chiếu và ghi cảnh báo phần chưa liên kết. |
| api | Dịch mã bằng API | module | Dịch C sang C# hoặc hoàn thiện C# decompile qua Chat Completions tương thích OpenAI. |
| analyze | Phân tích APK | capability | Điều phối luồng IL2CPP/DEX; có thể lấy thêm Java ở job Unity. |
| browse | Duyệt class / method | capability | Đọc SQLite, tìm class và hiển thị chữ ký/RVA/trạng thái/pseudocode. |
| resume | Tiếp tục job | capability | Đọc cấu hình và đầu vào job cũ, giữ nhóm đã chọn, tận dụng kết quả đã có. |
| retry | Thử lại hàm lỗi | capability | Chỉ chạy lại hàm native thiếu thân; các timeout thử lại là 120 và 180 giây. |
| recover | Khôi phục XOR metadata đã biết | capability | Hỗ trợ wrapper có khóa cố định được đánh dấu trong libil2cpp.so và biến thể Il2cppEncrtypt có khóa DWORD nhúng (kl 130–140); xác thực header/nội dung, ghi sidecar và giữ metadata gốc. |
| scope | Chọn phạm vi decompile | capability | Lập danh sách native method theo nhóm mà vẫn giữ metadata đầy đủ. Mặc định nhóm game. |
| batch | Lưu native theo lô | capability | Ghidra xuất lô tối đa 1.000 phương thức; Python nhập kết quả và gom file theo class. |
| enum | Ánh xạ mechanic từ enum | capability | Đối chiếu ID có ngữ nghĩa với enum metadata của APK; giữ ID gốc, không đoán khi thiếu/mơ hồ. |
| api_test | Kiểm tra API / model | capability | Gửi yêu cầu thử nhỏ, kiểm tra model trả nội dung; yêu cầu có thể tính phí. |
| api_export | Dịch lô C / C# qua API | capability | Đọc một file hoặc cây thư mục; từng file được xử lý độc lập, lưu cây kết quả riêng và báo cáo. |
| packages | APK / XAPK / APKS / split | input | Các split phải cùng bản game; ZIP container và đầu vào binary/metadata rời cũng được đọc. |
| binary | libil2cpp.so | input | Native binary chứa code IL2CPP; cần ghép với metadata của cùng bản. |
| metadata_dat | global-metadata.dat | input | Tên class/method, chữ ký và metadata IL2CPP; parser cần đọc được định dạng. |
| dex | DEX Android | input | Bytecode Java/Kotlin trong APK; có thể tồn tại cùng IL2CPP. |
| bundles | Unity bundles / TextAsset | input | Asset/config trong gói; bundle mã hóa riêng cần codec tương ứng. |
| c_input | File C / pseudocode | input | File .c UTF-8, có thể chứa pseudocode Ghidra, metadata comments và RVA. |
| cs_input | File C# decompile | input | File .cs UTF-8 được dùng làm đầu vào hoàn thiện cú pháp/khả năng đọc. |
| il2cpp_core_workflow | Quy trình lõi Unity IL2CPP | capability | Tri thức vận hành được job áp dụng: ghép libil2cpp.so với global-metadata.dat; chọn Il2CppDumper hoặc Cpp2IL theo phiên bản/kết quả parser; dùng Ghidra headless tạo pseudocode native từ RVA. Metadata/pseudocode không phải source C# gốc; metadata mã hóa tùy biến cần codec/khóa riêng. |
| ghidra_csharp_knowledge | Tri thức dịch pseudocode IL2CPP sang C# | concept | Prompt đang được áp dụng khi dịch file .c qua API: xem C là pseudocode native, giữ class/method/RVA, bảo toàn luồng điều khiển và phép toán có bằng chứng, giữ truy cập pointer/offset tường minh, không đoán gameplay/layout; vùng thiếu được ghi TODO/stub. Khuyến nghị kiểm tra bằng Roslyn nhưng tool chưa tự chạy compiler. |
| dumper | Il2CppDumper | dependency | Parser IL2CPP lấy script.json và dump.cs; khi không phù hợp có thể chuyển Cpp2IL. |
| cpp2il | Cpp2IL | dependency | Parser/ánh xạ thay thế; cần xác định phiên bản Unity và dùng .NET riêng của tool. |
| ghidra | Ghidra headless | dependency | Decompiler native được gọi qua analyzeHeadless; tạo pseudocode từ địa chỉ đã lập chỉ mục. |
| ghidra_script | DucAPKDecompile.java | dependency | Script Ghidra đọc method manifest và xuất kết quả/trạng thái; tận dụng lô đã xử lý. |
| jadx | JADX | dependency | Decompiler DEX sang Java; fallback không thay thế phần IL2CPP bị lỗi. |
| unitypy | UnityPy | dependency | Đọc Unity assets và bundles để lấy TextAsset và dữ liệu object. |
| crypto | PyCryptodome | dependency | Giải mã AES-CBC cho PackageManifest YooAsset theo định dạng được hỗ trợ. |
| dotnet | .NET runtime riêng | dependency | tools/dotnet/dotnet.exe chạy Cpp2IL. |
| llm | API model bên ngoài / local | dependency | POST Chat Completions với model, messages, stream=false; dùng Base URL do người dùng nhập. |
| job | Job / job.json | artifact | Một phiên phân tích: đầu vào, lựa chọn nhóm, backend, trạng thái và báo cáo; dùng cho resume. |
| sqlite | methods.sqlite | artifact | Các bảng methods, selected_methods, results liên kết metadata, phạm vi và pseudocode/trạng thái. |
| class_index | class_index.csv | artifact | Mục lục class tạo từ metadata. |
| class_meta | classes_metadata/ | artifact | Khai báo class/method/signature/RVA; method không ánh xạ được vẫn được giữ. |
| manifest | methods.tsv / selected.tsv | artifact | Danh sách method và phạm vi native cần Ghidra xử lý. |
| c_output | classes_c/ | artifact | Pseudocode chia thành game_logic, unity_dotnet và third_party_sdk. |
| dump | dump.cs / method map | artifact | dump.cs là khai báo metadata; Cpp2IL cung cấp bảng ánh xạ method thay thế. |
| java_output | java_source/sources/ | artifact | Mã Java decompile từ DEX qua JADX. |
| level_output | levels/ + levels.json | artifact | JSON từng level và manifest nguồn/lỗi/bundle/pack/mechanic. |
| analysis_report | report.json / failed_functions.json | artifact | Số hàm có/thiếu thân, lỗi decompile và thông tin cần retry. |
| log | activity.log | artifact | Nhật ký phân tích và tiến độ theo thời gian. |
| project | DucAPK.gpr | artifact | Project Ghidra riêng dưới projects/job_<mã>/. |
| offline_output | C# offline + report | artifact | Cây .cs tham chiếu và translation_report.json ghi stub/cảnh báo. |
| api_output | C# API + report | artifact | Cây .cs riêng và api_translation_report.json; status needs_review, compiled=false. |
| game | Logic game | concept | Nhóm mặc định; namespace chưa được nhận diện cũng thuộc nhóm này. |
| unity | Unity / .NET | concept | Nhóm class framework được phân loại theo namespace. |
| sdk | SDK bên thứ ba | concept | Nhóm SDK/thư viện được nhận diện theo các prefix đã cấu hình. |
| hdpk | Codec HDPK | concept | Đọc bảng offset và xuất bản ghi JSON level theo schema đã hỗ trợ. |
| msgpack | Codec MessagePack puzzle | concept | Bộ unpack và nhận diện cấu trúc puzzle được hỗ trợ. |
| juicetime | Schema JuiceTime | concept | Nhận diện và bung payload level thành nhóm/xiên/màu/trạng thái; giữ chuỗi thô. |
| yooasset | PackageManifest / BundleStream | concept | Ánh xạ tên bundle, giải mã manifest và đảo biến đổi bundle theo format đã biết. |
| review | C# cần rà soát / compile | constraint | Pseudocode và C# tái dựng không được bảo đảm là source gốc hay tương đương; có TODO/stub. |
| local | Phân tích chạy local | constraint | Phân tích và dịch offline chạy trên máy; tool không tự tải APK lên API. |
| api_boundary | Gửi file khi bấm dịch API | constraint | Chỉ gửi nội dung file C/C# đã chọn; có thể tính phí, xử lý độc lập mỗi file, tối đa 240.000 byte UTF-8. |
| api_key | API Key trong phiên | constraint | Key được che; có thể đọc DUCAPK_API_KEY, không ghi trong báo cáo; không chuyển tiếp credential qua redirect. |
| api_safety | Kiểm tra phản hồi API | constraint | Từ chối đầu ra bị cắt/chặn/sai định dạng; dừng lô khi lỗi kết nối/key/quota; HTTPS từ xa, HTTP localhost. |
| limits | Giới hạn parser / codec | constraint | Không có bộ giải mã chung cho mọi APK/metadata/bundle; tên đã obfuscate và logic thiếu không tự khôi phục. |
| knowledge_view | Trình xem Knowledge Graph | module | Tab desktop native: tìm thực thể, chọn nút lân cận, xem quan hệ có hướng và căn cứ source; đọc JSON local. |
| explore_graph | Khám phá tri thức tool | capability | Chọn thực thể trong danh sách hoặc graph, xem quan hệ đi vào/đi ra, mô tả và file/dòng căn cứ; tải lại dữ liệu. |
| ghidra_source_view | Tra cứu source Ghidra | module | Giao diện tìm source Ghidra đã đồng bộ, hiển thị đường dẫn, dòng và đoạn mã khớp. |
| sync_ghidra_source | Cập nhật kiến thức Ghidra | capability | Đồng bộ sparse checkout các module source chính thức từ GitHub và dựng lại chỉ mục SQLite FTS5 trong worker nền. |
| search_ghidra_source | Tìm trong source Ghidra | capability | Tìm từ khóa trong source đã lập chỉ mục và trả về file, dòng cùng đoạn trích. |
| graph_data | Knowledge Graph JSON | artifact | knowledge/ducapk_knowledge_graph.json: thực thể, quan hệ có hướng, nhãn quan hệ, evidence và SHA-256 của source; snapshot biên tập về tool. |
| graph_builder | Dựng snapshot tri thức | module | Script biên tập facts, lấy dòng symbol bằng AST, kiểm tra ID/quan hệ và xuất graph JSON cùng bảng Markdown; cần rà facts khi source đổi. |
| ghidra_source_checkout | Checkout source Ghidra | artifact | knowledge/ghidra_upstream/: shallow/sparse checkout của repo chính thức, giới hạn vào các module được chọn. |
| ghidra_source_index | Chỉ mục source Ghidra | artifact | knowledge/ghidra_source_index.sqlite3: nội dung source văn bản và metadata commit dùng cho truy vấn FTS5. |

## Các bộ ba quan hệ

| Chủ thể | Quan hệ | Đối tượng | Căn cứ |
|---|---|---|---|
| DucAPK | có giao diện | Giao diện desktop | app.py:1 |
| DucAPK | có giao diện | Command line | cli.py:1 |
| DucAPK | có module | Điều phối phân tích | ducapk/runner.py:1 |
| DucAPK | có module | Đọc gói APK | ducapk/archive.py:1 |
| DucAPK | có module | Lập chỉ mục metadata | ducapk/metadata.py:1 |
| DucAPK | có module | Phân nhóm class | ducapk/categories.py:1 |
| DucAPK | có module | Trích dữ liệu level | ducapk/levels.py:1 |
| DucAPK | có module | Dịch C → C# offline | ducapk/csharp_export.py:1 |
| DucAPK | có module | Dịch mã bằng API | ducapk/api_translation.py:1 |
| DucAPK | có module | Trình xem Knowledge Graph | README.md:1 |
| DucAPK | có module | Dựng snapshot tri thức | README.md:1 |
| DucAPK | có module | Tra cứu source Ghidra | README.md:1 |
| Giao diện desktop | cung cấp | Khám phá tri thức tool | app.py:222 |
| Trình xem Knowledge Graph | triển khai | Khám phá tri thức tool | ducapk/knowledge_view.py:18 |
| Trình xem Knowledge Graph | đọc đầu vào | Knowledge Graph JSON | ducapk/knowledge_view.py:18 |
| Khám phá tri thức tool | đọc đầu vào | Knowledge Graph JSON | ducapk/knowledge_view.py:119 |
| Dựng snapshot tri thức | tạo ra | Knowledge Graph JSON | scripts/build_knowledge_graph.py:1 |
| Giao diện desktop | cung cấp | Cập nhật kiến thức Ghidra | app.py:222 |
| Giao diện desktop | cung cấp | Tìm trong source Ghidra | app.py:222 |
| Tra cứu source Ghidra | triển khai | Cập nhật kiến thức Ghidra | ducapk/ghidra_knowledge.py:206 |
| Tra cứu source Ghidra | triển khai | Tìm trong source Ghidra | ducapk/ghidra_knowledge.py:206 |
| Cập nhật kiến thức Ghidra | cập nhật | Checkout source Ghidra | ducapk/ghidra_knowledge.py:133 |
| Cập nhật kiến thức Ghidra | tạo ra | Chỉ mục source Ghidra | ducapk/ghidra_knowledge.py:133 |
| Tìm trong source Ghidra | đọc đầu vào | Chỉ mục source Ghidra | ducapk/ghidra_knowledge.py:181 |
| Giao diện desktop | gọi | Phân tích APK | app.py:222 |
| Command line | gọi | Phân tích APK | cli.py:12 |
| Giao diện desktop | cung cấp | Duyệt class / method | app.py:222 |
| Giao diện desktop | cung cấp | Dịch mã bằng API | app.py:222 |
| Giao diện desktop | cung cấp | Dịch C → C# offline | app.py:222 |
| Giao diện desktop | cung cấp | Tiếp tục job | app.py:222 |
| Command line | cung cấp | Tiếp tục job | cli.py:12 |
| Giao diện desktop | cung cấp | Thử lại hàm lỗi | app.py:222 |
| Điều phối phân tích | triển khai | Phân tích APK | ducapk/runner.py:1 |
| Điều phối phân tích | triển khai | Tiếp tục job | ducapk/runner.py:1 |
| Điều phối phân tích | triển khai | Thử lại hàm lỗi | ducapk/runner.py:1 |
| Điều phối phân tích | triển khai | Khôi phục XOR metadata đã biết | ducapk/runner.py:1 |
| Điều phối phân tích | triển khai | Chọn phạm vi decompile | ducapk/runner.py:1 |
| Điều phối phân tích | triển khai | Lưu native theo lô | ducapk/runner.py:1 |
| Phân tích APK | sử dụng | Quy trình lõi Unity IL2CPP | ducapk/runner.py:1050 |
| Quy trình lõi Unity IL2CPP | gọi | Il2CppDumper | ducapk/runner.py:1050 |
| Quy trình lõi Unity IL2CPP | chuyển sang khi không phù hợp | Cpp2IL | ducapk/runner.py:1050 |
| Quy trình lõi Unity IL2CPP | gọi | Ghidra headless | ducapk/runner.py:1050 |
| Phân tích APK | gọi | Đọc gói APK | ducapk/runner.py:1050 |
| Phân tích APK | gọi | Lập chỉ mục metadata | ducapk/runner.py:1050 |
| Phân tích APK | gọi | Trích dữ liệu level | ducapk/runner.py:1050 |
| Phân tích APK | gọi | Chọn phạm vi decompile | ducapk/runner.py:1050 |
| Phân tích APK | gọi | Lưu native theo lô | ducapk/runner.py:1050 |
| Phân tích APK | gọi | Thử lại hàm lỗi | ducapk/runner.py:1050 |
| Đọc gói APK | đọc đầu vào | APK / XAPK / APKS / split | ducapk/archive.py:1 |
| Đọc gói APK | trích xuất | libil2cpp.so | ducapk/archive.py:1 |
| Đọc gói APK | trích xuất | global-metadata.dat | ducapk/archive.py:1 |
| Điều phối phân tích | gọi | Il2CppDumper | ducapk/runner.py:1 |
| Điều phối phân tích | gọi | Cpp2IL | ducapk/runner.py:1 |
| Điều phối phân tích | gọi | JADX | ducapk/runner.py:1 |
| Il2CppDumper | chuyển sang khi không phù hợp | Cpp2IL | ducapk/runner.py:499 |
| Cpp2IL | sử dụng | .NET runtime riêng | ducapk/runner.py:468 |
| Il2CppDumper | đọc đầu vào | libil2cpp.so | ducapk/runner.py:499 |
| Il2CppDumper | đọc đầu vào | global-metadata.dat | ducapk/runner.py:499 |
| Cpp2IL | đọc đầu vào | libil2cpp.so | ducapk/runner.py:468 |
| Cpp2IL | đọc đầu vào | global-metadata.dat | ducapk/runner.py:468 |
| Il2CppDumper | tạo ra | dump.cs / method map | ducapk/runner.py:499 |
| Cpp2IL | tạo ra | dump.cs / method map | ducapk/runner.py:468 |
| Khôi phục XOR metadata đã biết | đọc đầu vào | global-metadata.dat | ducapk/runner.py:50 |
| Khôi phục XOR metadata đã biết | sử dụng | libil2cpp.so | ducapk/runner.py:50 |
| Lập chỉ mục metadata | đọc đầu vào | dump.cs / method map | ducapk/metadata.py:1 |
| Lập chỉ mục metadata | tạo ra | methods.sqlite | ducapk/metadata.py:1 |
| Lập chỉ mục metadata | tạo ra | classes_metadata/ | ducapk/metadata.py:1 |
| Lập chỉ mục metadata | tạo ra | class_index.csv | ducapk/metadata.py:1 |
| Lập chỉ mục metadata | tạo ra | methods.tsv / selected.tsv | ducapk/metadata.py:1 |
| Chọn phạm vi decompile | sử dụng | Phân nhóm class | ducapk/runner.py:171 |
| Chọn phạm vi decompile | đọc đầu vào | methods.tsv / selected.tsv | ducapk/runner.py:171 |
| Chọn phạm vi decompile | cập nhật | methods.sqlite | ducapk/runner.py:171 |
| Phân nhóm class | phân nhóm | Logic game | ducapk/categories.py:1 |
| Phân nhóm class | phân nhóm | Unity / .NET | ducapk/categories.py:1 |
| Phân nhóm class | phân nhóm | SDK bên thứ ba | ducapk/categories.py:1 |
| Lưu native theo lô | gọi | Ghidra headless | ducapk/runner.py:642 |
| Ghidra headless | chạy script | DucAPKDecompile.java | ducapk/runner.py:557 |
| DucAPKDecompile.java | đọc đầu vào | methods.tsv / selected.tsv | scripts/DucAPKDecompile.java:1 |
| Ghidra headless | đọc đầu vào | libil2cpp.so | ducapk/runner.py:557 |
| Lưu native theo lô | cập nhật | methods.sqlite | ducapk/runner.py:642 |
| Điều phối phân tích | tạo ra | classes_c/ | ducapk/runner.py:1 |
| Ghidra headless | tạo ra | DucAPK.gpr | ducapk/runner.py:557 |
| Điều phối phân tích | tạo ra | report.json / failed_functions.json | ducapk/runner.py:1 |
| Điều phối phân tích | tạo ra | Job / job.json | ducapk/runner.py:1 |
| Điều phối phân tích | tạo ra | activity.log | ducapk/runner.py:1 |
| Tiếp tục job | đọc đầu vào | Job / job.json | ducapk/runner.py:1050 |
| Thử lại hàm lỗi | đọc đầu vào | methods.sqlite | ducapk/runner.py:786 |
| Thử lại hàm lỗi | gọi | Ghidra headless | ducapk/runner.py:786 |
| Thử lại hàm lỗi | cập nhật | classes_c/ | ducapk/runner.py:786 |
| Thử lại hàm lỗi | cập nhật | report.json / failed_functions.json | ducapk/runner.py:786 |
| Duyệt class / method | đọc đầu vào | methods.sqlite | app.py:1553 |
| JADX | đọc đầu vào | DEX Android | ducapk/runner.py:294 |
| JADX | tạo ra | java_source/sources/ | ducapk/runner.py:294 |
| Trích dữ liệu level | đọc đầu vào | APK / XAPK / APKS / split | ducapk/levels.py:1 |
| Trích dữ liệu level | đọc đầu vào | Unity bundles / TextAsset | ducapk/levels.py:1 |
| Trích dữ liệu level | sử dụng | UnityPy | ducapk/levels.py:1 |
| Trích dữ liệu level | sử dụng | PyCryptodome | ducapk/levels.py:1 |
| Trích dữ liệu level | hỗ trợ định dạng | Codec HDPK | ducapk/levels.py:1 |
| Trích dữ liệu level | hỗ trợ định dạng | Codec MessagePack puzzle | ducapk/levels.py:1 |
| Trích dữ liệu level | hỗ trợ định dạng | Schema JuiceTime | ducapk/levels.py:1 |
| Trích dữ liệu level | hỗ trợ định dạng | PackageManifest / BundleStream | ducapk/levels.py:1 |
| Trích dữ liệu level | triển khai | Ánh xạ mechanic từ enum | ducapk/levels.py:1 |
| Ánh xạ mechanic từ enum | đọc đầu vào | dump.cs / method map | ducapk/levels.py:501 |
| Ánh xạ mechanic từ enum | làm giàu dữ liệu | levels/ + levels.json | ducapk/levels.py:501 |
| Trích dữ liệu level | tạo ra | levels/ + levels.json | ducapk/levels.py:1 |
| Dịch C → C# offline | đọc đầu vào | File C / pseudocode | ducapk/csharp_export.py:1 |
| Dịch C → C# offline | đọc đầu vào | classes_c/ | ducapk/csharp_export.py:1 |
| Dịch C → C# offline | tạo ra | C# offline + report | ducapk/csharp_export.py:1 |
| Dịch mã bằng API | triển khai | Kiểm tra API / model | ducapk/api_translation.py:1 |
| Dịch mã bằng API | triển khai | Dịch lô C / C# qua API | ducapk/api_translation.py:1 |
| Kiểm tra API / model | gọi | API model bên ngoài / local | ducapk/api_translation.py:86 |
| Dịch lô C / C# qua API | gọi | API model bên ngoài / local | ducapk/api_translation.py:146 |
| Dịch lô C / C# qua API | sử dụng | Tri thức dịch pseudocode IL2CPP sang C# | ducapk/api_translation.py:146 |
| Dịch lô C / C# qua API | đọc đầu vào | File C / pseudocode | ducapk/api_translation.py:146 |
| Dịch lô C / C# qua API | đọc đầu vào | File C# decompile | ducapk/api_translation.py:146 |
| Dịch lô C / C# qua API | đọc đầu vào | classes_c/ | ducapk/api_translation.py:146 |
| Dịch lô C / C# qua API | tạo ra | C# API + report | ducapk/api_translation.py:146 |
| Dịch mã bằng API | chịu giới hạn | Gửi file khi bấm dịch API | ducapk/api_translation.py:1 |
| Dịch mã bằng API | chịu giới hạn | API Key trong phiên | ducapk/api_translation.py:1 |
| Dịch mã bằng API | chịu giới hạn | Kiểm tra phản hồi API | ducapk/api_translation.py:1 |
| C# API + report | cần | C# cần rà soát / compile | ducapk/api_translation.py:146 |
| C# offline + report | cần | C# cần rà soát / compile | ducapk/csharp_export.py:413 |
| classes_c/ | cần | C# cần rà soát / compile | ducapk/runner.py:846 |
| DucAPK | chịu giới hạn | Giới hạn parser / codec | README.md:1 |
| Phân tích APK | chịu giới hạn | Phân tích chạy local | ducapk/runner.py:1050 |
| Dịch C → C# offline | chịu giới hạn | Phân tích chạy local | ducapk/csharp_export.py:1 |

Để dựng lại: `python scripts/build_knowledge_graph.py`. Các facts được biên tập trong script; cần rà lại khi source đổi.
