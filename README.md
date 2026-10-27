# DucAPK

Ứng dụng Windows để phân tích APK Android: xuất danh sách class/phương thức, mã giải mã theo từng class và dữ liệu level của game.

## Cài đặt và mở ứng dụng

1. Clone repo hoặc tải source ZIP rồi giải nén trên **Windows x64**.
2. Nhấp đúp **`Setup.bat`** một lần. Cần Internet để tải bộ runtime từ GitHub Release (khoảng 890 MB; dung lượng chính xác ghi trong `runtime-manifest.json`). Setup kiểm tra SHA-256, giải nén Python, .NET, Il2CppDumper, Cpp2IL, JADX, Ghidra và JDK vào `tools/`, rồi cài thư viện Python từ các wheel đi kèm. Không cần cài Python/Java/.NET thủ công hoặc quyền Administrator.
3. Nhấp đúp **`DucAPK.bat`** để mở ứng dụng. Nếu chưa có môi trường Python, launcher sẽ gọi Setup trước.

Sau lần cài đầu, các chức năng phân tích chạy offline; API dịch mã và cập nhật source tham khảo vẫn cần kết nối tương ứng. Khi cập nhật source, chạy `git pull`; nếu dependency thay đổi thì chạy lại Setup. Các archive được giữ trong `tools/runtime-cache/` để cài lại không phải tải lại.

Nếu chuyển thư mục app sang đường dẫn khác, chạy lại `Setup.bat` để cập nhật môi trường Python.

Source ở Git; binary nặng ở **[GitHub Releases](https://github.com/daothdat10/ToolDucAPK/releases)**. `tools/`, APK, job và kết quả giải mã không được commit. Xem [THIRD_PARTY.md](THIRD_PARTY.md) để biết thành phần và source snapshot của tool tùy chỉnh.

### Dùng bộ công cụ có sẵn

Mặc định tool tự tìm runtime trong repo. Có thể sao chép `tool_paths.example.json` thành `tool_paths.json` rồi sửa đường dẫn; file cấu hình cá nhân được Git bỏ qua. Biến môi trường `DUCAPK_GHIDRA`, `DUCAPK_JAVA_HOME`, `DUCAPK_DOTNET`, `DUCAPK_CPP2IL`, `DUCAPK_IL2CPP_DIR`, `DUCAPK_JADX` ưu tiên cao hơn cấu hình file. Máy hiện tại vẫn dùng được các bản Ghidra/JDK đã có nếu chưa cài bộ portable.

Kiểm tra bộ công cụ bằng `.venv\Scripts\python.exe -m ducapk.toolchain`. Chạy CLI và test bằng Python trong `.venv`, ví dụ `.venv\Scripts\python.exe cli.py --help`.

### Cài offline hoặc tải trước

Tải đủ ba archive được liệt kê trong `runtime-manifest.json` từ Release, đặt chung trong một thư mục, rồi chạy `Setup.bat -CacheDirectory "D:\RuntimeCache"`. Setup vẫn xác minh checksum và cài Python dependencies hoàn toàn từ wheel đi kèm. Không cần tải archive source snapshot để chạy app. Có thể dùng `Setup.bat -Force` để giải nén lại runtime.

## 01 Phân tích APK

1. Kéo file `.apk`/`.xapk`/`.apks` vào vùng thả. Với split APK, chọn toàn bộ các split của **cùng một phiên bản game**.
2. Chọn thư mục kết quả (mặc định là `output/`).
3. Chọn nhóm mã cần giải mã:
   - **Logic game / code riêng của studio** (bật sẵn).
   - **Unity/.NET framework**.
   - **SDK + tích hợp quảng cáo, IAP, analytics**.
4. Chọn tùy chọn xuất:
   - **Tạo thân hàm C**: bỏ chọn nếu chỉ cần danh sách class/phương thức.
   - **Trích dữ liệu level Unity → levels.json** (bật sẵn).
   - **Giải mã Java/DEX (SDK Android)** (tắt sẵn): với game Unity, phần này gần như chỉ có SDK. Chỉ bật khi cần xem code Java/Kotlin.
   - **Giải mã game native C/C++ (engine riêng)** (tắt sẵn): dùng cho Gardenscapes và các APK native. Khi không có Unity IL2CPP, tool tìm hàm trong các thư viện `.so` qua bảng `.eh_frame_hdr` (có sẵn trong hầu hết thư viện C++, kể cả bản đã strip) thay cho Auto Analyze toàn cục: `libgame.so` 117MB của Gardenscapes có 303.473 hàm, tìm xong trong khoảng 7 phút. Tool cũng gắn tên hàm import cho các stub `.plt` (ví dụ `strncmp`, `__system_property_get`) và tạo chuỗi trong `.rodata` để mã giả hiện chuỗi thật. Thư viện không có `.eh_frame_hdr` vẫn dùng Auto Analyze (có thể mất nhiều giờ). Sau đó giải mã song song theo số luồng Ghidra, hàm có tên (export/JNI) được giải mã trước. Thư viện SDK/runtime (quảng cáo, crash reporter, FMOD, Sentry, libunity/libmain…) được xếp vào nhóm SDK theo tên và bỏ qua nếu chỉ chọn Logic game. Bật **Tạo thân hàm C** để xuất mã giả.
   - **Số luồng**: số tiến trình giải mã chạy song song. Máy yếu hoặc ít RAM thì nên giảm.
5. Bấm **PHÂN TÍCH**.

Trong lúc chạy, thanh trạng thái hiện tiến độ, tốc độ (hàm/giây), thời gian còn lại và giờ dự kiến xong. Cứ mỗi 1.000 hàm, log ghi thêm một dòng `ETA:`. Thời gian dự kiến chưa gồm vòng thử lại và bước xuất file ở cuối. Job lớn có thể chạy nhiều giờ.

- **Dừng sau khi lưu**: dừng job, phần đã làm vẫn được giữ.
- **Tiếp tục job**: chọn thư mục job đã dừng để chạy tiếp. Job tiếp tục dùng các nhóm mã đã chọn lúc tạo. Muốn đổi nhóm thì tạo job mới.
- **Thử lại hàm lỗi**: chỉ chạy lại những hàm chưa giải mã được, rồi cập nhật lại các file class.

Job chỉ được báo hoàn tất khi mọi hàm đã chọn đều có thân hàm. Nếu chưa đủ, job ở trạng thái làm một phần và có thể tiếp tục sau.

### Dòng lệnh

```
python cli.py <file.apk> [--category game --category unity --category sdk] [--threads N] [--no-java]
```

Game C/C++ dùng engine riêng, ví dụ Gardenscapes:

```
python cli.py "Gardenscapes_10.0.0_APKPure.xapk" --native --no-java
```

Native xuất vào `classes_c/native/`, chia mỗi file tối đa 500 hàm; có thể xem trong **Duyệt mã**. `native_libraries.json` ghi thư viện, ABI và cách phân nhóm theo tên (SDK chưa biết có thể được xếp vào Logic game). `native/<thư-viện>/ghidra_native_import.log` (bước tìm hàm) và `ghidra_native.log` (bước giải mã) lưu log; `function_starts.txt` là danh sách địa chỉ hàm đọc từ `.eh_frame_hdr`. **Tiếp tục job** và **Thử lại hàm lỗi** giữ các thân hàm đã thành công. Mã xuất là mã giả C từ binary, không khôi phục source C++ gốc hoặc dữ liệu level riêng của Playrix. Danh sách hàm phụ thuộc khả năng nhận diện của Ghidra; binary bị strip hoặc bảo vệ có thể chỉ phân tích được một phần.

Nếu không truyền `--category`, tool chỉ giải mã nhóm `game`.

## Kết quả

Kết quả nằm trong `output/<tên gói>_<thời gian>/` hoặc thư mục đã chọn:

- `classes_metadata/`: mỗi class một file, gồm tên phương thức, địa chỉ và chữ ký.
- `classes_c/game_logic/`, `classes_c/unity_dotnet/`, `classes_c/third_party_sdk/`: mã giải mã theo nhóm, mỗi class một file `.c`.
  - Class có namespace nằm theo cây namespace, tối đa 5 cấp. Ví dụ `Cysharp.Threading.Tasks.UniTask` nằm ở `third_party_sdk/Cysharp/Threading/Tasks/`.
  - Class lồng nhau nằm cùng thư mục với class chứa nó.
  - Class không có namespace nằm trong `_NoNamespace/`. Ở nhóm game, các class này được chia tiếp thành `States`, `Systems`, `Data`, `Bootstrap`, `UI`, `Services`, `Tutorial`, `Boosters`, `Extensions` và `Other`.
- `class_index.csv`, `methods.sqlite`: mục lục để tìm kiếm trong tab **Duyệt mã**.
- `dump.cs`: cấu trúc class C# (không có thân hàm).
- `java_source/`: code Java/Kotlin, chỉ có khi bật ô giải mã Java/DEX.
- `levels.json` và thư mục `levels/`: dữ liệu level trích từ game.
- `LevelModel.cs`: class C# để đọc các file level trên. Nếu metadata có class level của game thì dùng đúng tên/kiểu/enum của game, thêm các field chỉ có trong JSON; nếu không thì suy toàn bộ từ JSON.
- `assemblies.json`: số hàm theo từng DLL và nhóm của DLL đó.
- `tech_stack.json`: engine, thư viện, SDK và shader game dùng (xem tab **Công nghệ**).
- `report.json`: thống kê số class, số phương thức, số hàm thành công và số hàm lỗi.
- `failed_functions.json`: danh sách hàm chưa giải mã được.
- `activity.log`: nhật ký của job.

## 02 Duyệt mã

- Mở một job để tìm class và xem metadata hoặc mã của từng class.
- **Dịch C → C#**: chọn thư mục đích. Tool tạo thư mục `<tên-job>_CSharp` với các file `.cs` và `translation_report.json`. File nguồn không bị thay đổi. Kết quả dịch có thể còn hàm rỗng (stub), cần kiểm tra lại.

## 03 Công nghệ

Cho biết game được làm bằng gì, lấy bằng chứng trực tiếp từ APK. Kết quả quét được tự lưu vào `tech_stack.json` khi phân tích xong. Job cũ chưa có file này thì tab sẽ tự quét khi mở (mất khoảng 20 giây); bấm **Quét lại** để quét lần nữa.

- **Engine**: Unity (phiên bản, IL2CPP/Mono, render pipeline Built-in/URP/HDRP), Unreal, Cocos, Godot, Flutter...
- **Thư viện C#**: tween (DOTween, LitMotion), Spine, spline (Unity Splines, Dreamteck, Curvy, BG Curve, Path Creator...), DI (Zenject, VContainer), UniTask, R3, Odin, TextMeshPro, outline, mask UI...
- **SDK Android**: mạng quảng cáo, analytics/attribution, thanh toán, bảo vệ (PairIP), nhận qua thư viện `.so` và package trong `classes*.dex`.
- **Shader**: từng shader trong APK, thuộc thư viện nào hay là shader riêng của game, material nào dùng nó, các thuộc tính, và công dụng đoán từ tên/thuộc tính (stencil để che/cắt vùng, mask, viền, dissolve, VAT, instancing...).
- **Class game dùng nó**: các class của game có field, class cha hoặc tham số hàm thuộc kiểu của thư viện. Ví dụ class `RoadBuilder` có field `SplineComputer` nghĩa là đường đi được dựng bằng Dreamteck Splines. Mở class đó ở tab **Duyệt mã** để xem cách dùng.
- **Material gắn ở đâu**: khi chọn một shader, mỗi material của nó có danh sách chỗ gắn. Mỗi chỗ gồm renderer (`MeshRenderer`…) hoặc field của script (ví dụ `Image.m_Material`), đường dẫn object (`ScreenInGame/Root/…/Bg`), prefab/scene chứa nó và các script trên cùng object.
- **Material phục vụ cái gì** (dòng `⇒ phục vụ:`): suy ra từ ba nguồn. (1) Vùng: UI, hiệu ứng (FX) hay gameplay. (2) Script game trên object hoặc object cha gần nhất (ví dụ `IceGun`). (3) Cơ chế level trong `LevelModel.cs` có từ trùng với tên object/material (ví dụ `Gun/…/Ice/…` ↔ `GunData.IceHp`, `Dynamite` ↔ `GunObstacleType.Dynamite`). Material không gắn trên object nào chỉ được đoán theo tên (`⇒ đoán theo tên:`).
- **Tính năng game ← material**: tra ngược theo cơ chế level, script game hoặc màn hình UI để xem những material, prefab và object nào phục vụ nó.
- **Component trên object**: khi chọn một thư viện, tab liệt kê các component của thư viện đó đang gắn trên object nào. Ví dụ `EPOOutline.Outlinable` gắn trên `Gun/…/Outline` trong `Prefab Gun`.
- **Prefab & Scene**: từng prefab/scene cùng các script gắn trong đó và material được dùng. Tên lấy từ container của Addressables/AssetBundle (`Assets/…/X.prefab`), thư mục `Resources/…`, danh sách scene trong Build Settings, hoặc tên object gốc (`Prefab Gun · resources.assets`).
- **Script game gắn trên object**: script của game kèm số object có gắn script đó.
- **Thư viện chưa nhận diện**: các DLL SDK mà DucAPK chưa biết, thường là framework riêng của studio.

Material chỉ được code nạp lúc chạy, hoặc nằm trong script đã bị Unity bỏ typetree khi build (thường thấy với các file trong `data.unity3d`), sẽ được ghi là không tìm thấy chỗ gắn trực tiếp.

Công dụng của shader chỉ là phỏng đoán theo tên và thuộc tính. Thư viện mà game chỉ gắn qua prefab/Inspector, không nhắc tới trong code, sẽ không có danh sách class.

## 04 API dịch mã

1. Nhập **Base URL**, **API Key**, **Model** và timeout. Với OpenAI, Base URL là `https://api.openai.com/v1`. Với nhà cung cấp khác, dùng endpoint tương thích OpenAI Chat Completions của họ. Nếu dùng API chạy trên máy (localhost), có thể để trống key.
2. Bấm **Kiểm tra kết nối**. Lần gọi thử này có thể bị tính phí. API Key chỉ được giữ trong phiên đang mở; cũng có thể đặt qua biến môi trường `DUCAPK_API_KEY`.
3. Chọn một file `.c`/`.cs` hoặc một thư mục, hoặc bấm **Dùng classes_c của job**. Chọn nơi lưu nằm ngoài thư mục nguồn. Có thể nhập thêm yêu cầu riêng.
4. Bấm **DỊCH BẰNG API**. Kết quả được lưu vào `<tên-nguồn>_API_CSharp_<thời-gian>/`, kèm file `api_translation_report.json`.
5. **Dừng sau file hiện tại**: dừng sau khi file đang dịch xong. **Mở kết quả**: mở thư mục kết quả.

Mỗi file tối đa 240.000 byte. Kết quả do AI tạo ra cần người kiểm tra và biên dịch lại.

## 05 Knowledge Graph

- Nhập từ khóa vào **Tìm thực thể**, rồi bấm vào các nút trên sơ đồ để xem tiếp.
- **Về DucAPK**: quay về nút gốc. **Tải lại graph**: đọc lại dữ liệu.
- Nút **Cập nhật kiến thức** tải mã nguồn tham khảo (cần Git và Internet) để tra cứu theo từ khóa.

## 06 Level Editor

1. **APK / JOB**: chọn APK hoặc một job đã phân tích. Có thể kéo thả APK, thư mục job hoặc file `.cs` vào tab.
2. **LEVELDATA .CS**: chọn file hoặc thư mục chứa `LevelData.cs`. Chưa có thì để trống: tool tìm class level trong job (dump.cs), sinh `leveldata_from_apk/LevelData.cs` trong job rồi tạo editor từ đó. Nếu đoán sai class, chọn class khác ở **CLASS GỐC** và tạo lại.
3. **CLASS GỐC**: tên class đại diện cho một level, mặc định là `LevelData`.
4. Bấm **TẠO LEVEL EDITOR**. Nếu để trống ô **FILE HTML**, file được lưu trong thư mục job.

File `levelEditor.html` chạy offline trong trình duyệt:

- Thêm, nhân bản, xóa level, kéo thả để sắp xếp lại thứ tự.
- Form chỉnh sửa và bảng lưới được tạo tự động theo `LevelData.cs`.
- **Bàn chơi**: editor tự đoán cách vẽ level từ tên field (kích thước lưới, các lớp: tường, hố, object, snake, ô nền…). Hỗ trợ cả level lưu ô theo chỉ số phẳng (vd. `CubeDataIds`, `PixelIds`); thứ tự theo hàng/cột được suy từ level của game: chọn màu rồi tô/kéo trên lưới.
- **Luật game suy từ APK**: tool kiểm tra trên toàn bộ level đã trích. Ví dụ game kiểu bắn pixel (súng có màu + số đạn): nếu tổng đạn mỗi màu luôn bằng số pixel (+ khối trong ống), editor bật khu vực **cột súng** giống màn hình game, bảng cân bằng màu, **Tự sinh súng từ bức tranh** và **Cân bằng tự động**; level lệch màu được báo lỗi. Màu hiển thị theo enum màu của game (tên đúng, sắc độ gần đúng). Bấm **⚙ Thiết lập bàn chơi** để sửa bằng menu chọn, không cần viết code.
- Bấm **Xuất levelEditor.profile.json** và đặt file cạnh `LevelData.cs`; lần tạo editor sau sẽ dùng lại thiết lập này. Có thể chép file sang game cùng thể loại rồi chỉnh tên field.
- Trên bàn chơi: chọn lớp rồi đặt/vẽ/tô; **➤ Chọn** để sửa hoặc kéo di chuyển; chuột phải để xóa. Cơ chế của game (lấy từ APK) được thêm cho từng object, kèm form tham số.
- Game kiểu Gecko/Snake Out (luật "snake ra hố cùng màu") có thêm **▶ Chơi thử** và **⚙ Kiểm tra giải được**.
- Tab **Level từ APK**: bấm **Nhập** để lấy level có sẵn trong game.
- Tab **Kiểm tra**: báo các giá trị không hợp lệ.
- Xuất từng level (`Level N.json`), xuất tất cả thành `.zip` hoặc thành một file JSON chứa mảng level.

## 07 README

Tab này hiển thị file README này. Bấm **Tải lại** sau khi sửa file.

## Lưu ý

- Không phải APK nào cũng phân tích được. APK bị mã hóa hoặc bảo vệ riêng có thể không đọc được.
- Tên class bị làm rối (obfuscate) không thể khôi phục về tên gốc.
- Mã giải mã là bản dựng lại từ mã máy, không phải source gốc của game.
- Việc phân tích chạy hoàn toàn trên máy. Tab API chỉ gửi nội dung file đã chọn khi bạn bấm dịch.
