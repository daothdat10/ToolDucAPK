# DucAPK

Ứng dụng Windows để phân tích APK Android: xuất danh sách class/phương thức, mã giải mã theo từng class và dữ liệu level của game.

## Cài đặt và mở ứng dụng

1. Chạy một lần lệnh `python -m pip install -r requirements.txt`.
2. Nhấp đúp `DucAPK.bat` để mở ứng dụng.

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
   - **Giải mã game native C/C++ (engine riêng)** (tắt sẵn): dùng cho Gardenscapes và các APK native. Khi không có Unity IL2CPP, dùng Ghidra Auto Analyze để tìm và giải mã hàm trong các thư viện `.so`. Nhóm Logic game/SDK được chọn theo tên thư viện; Unity/.NET chỉ áp dụng cho IL2CPP. Bật **Tạo thân hàm C** để xuất mã giả. Quá trình tìm hàm có thể mất nhiều giờ.
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

Native xuất vào `classes_c/native/`, chia mỗi file tối đa 500 hàm; có thể xem trong **Duyệt mã**. `native_libraries.json` ghi thư viện, ABI và cách phân nhóm theo tên (SDK chưa biết có thể được xếp vào Logic game). `native/<thư-viện>/ghidra_native.log` lưu log. **Tiếp tục job** và **Thử lại hàm lỗi** giữ các thân hàm đã thành công. Mã xuất là mã giả C từ binary, không khôi phục source C++ gốc hoặc dữ liệu level riêng của Playrix. Danh sách hàm phụ thuộc khả năng nhận diện của Ghidra; binary bị strip hoặc bảo vệ có thể chỉ phân tích được một phần.

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
- `assemblies.json`: số hàm theo từng DLL và nhóm của DLL đó.
- `report.json`: thống kê số class, số phương thức, số hàm thành công và số hàm lỗi.
- `failed_functions.json`: danh sách hàm chưa giải mã được.
- `activity.log`: nhật ký của job.

## 02 Duyệt mã

- Mở một job để tìm class và xem metadata hoặc mã của từng class.
- **Dịch C → C#**: chọn thư mục đích. Tool tạo thư mục `<tên-job>_CSharp` với các file `.cs` và `translation_report.json`. File nguồn không bị thay đổi. Kết quả dịch có thể còn hàm rỗng (stub), cần kiểm tra lại.

## 03 API dịch mã

1. Nhập **Base URL**, **API Key**, **Model** và timeout. Với OpenAI, Base URL là `https://api.openai.com/v1`. Với nhà cung cấp khác, dùng endpoint tương thích OpenAI Chat Completions của họ. Nếu dùng API chạy trên máy (localhost), có thể để trống key.
2. Bấm **Kiểm tra kết nối**. Lần gọi thử này có thể bị tính phí. API Key chỉ được giữ trong phiên đang mở; cũng có thể đặt qua biến môi trường `DUCAPK_API_KEY`.
3. Chọn một file `.c`/`.cs` hoặc một thư mục, hoặc bấm **Dùng classes_c của job**. Chọn nơi lưu nằm ngoài thư mục nguồn. Có thể nhập thêm yêu cầu riêng.
4. Bấm **DỊCH BẰNG API**. Kết quả được lưu vào `<tên-nguồn>_API_CSharp_<thời-gian>/`, kèm file `api_translation_report.json`.
5. **Dừng sau file hiện tại**: dừng sau khi file đang dịch xong. **Mở kết quả**: mở thư mục kết quả.

Mỗi file tối đa 240.000 byte. Kết quả do AI tạo ra cần người kiểm tra và biên dịch lại.

## 04 Knowledge Graph

- Nhập từ khóa vào **Tìm thực thể**, rồi bấm vào các nút trên sơ đồ để xem tiếp.
- **Về DucAPK**: quay về nút gốc. **Tải lại graph**: đọc lại dữ liệu.
- Nút **Cập nhật kiến thức** tải mã nguồn tham khảo (cần Git và Internet) để tra cứu theo từ khóa.

## 05 Level Editor

1. **APK / JOB**: chọn APK hoặc một job đã phân tích. Có thể kéo thả APK, thư mục job hoặc file `.cs` vào tab.
2. **LEVELDATA .CS**: chọn file hoặc thư mục chứa `LevelData.cs`.
3. **CLASS GỐC**: tên class đại diện cho một level, mặc định là `LevelData`.
4. Bấm **TẠO LEVEL EDITOR**. Nếu để trống ô **FILE HTML**, file được lưu trong thư mục job.

File `levelEditor.html` chạy offline trong trình duyệt:

- Thêm, nhân bản, xóa level, kéo thả để sắp xếp lại thứ tự.
- Form chỉnh sửa và bảng lưới được tạo tự động theo `LevelData.cs`.
- Tab **Level từ APK**: bấm **Nhập** để lấy level có sẵn trong game.
- Tab **Kiểm tra**: báo các giá trị không hợp lệ.
- Xuất từng level (`Level N.json`), xuất tất cả thành `.zip` hoặc thành một file JSON chứa mảng level.

## 06 README

Tab này hiển thị file README này. Bấm **Tải lại** sau khi sửa file.

## Lưu ý

- Không phải APK nào cũng phân tích được. APK bị mã hóa hoặc bảo vệ riêng có thể không đọc được.
- Tên class bị làm rối (obfuscate) không thể khôi phục về tên gốc.
- Mã giải mã là bản dựng lại từ mã máy, không phải source gốc của game.
- Việc phân tích chạy hoàn toàn trên máy. Tab API chỉ gửi nội dung file đã chọn khi bạn bấm dịch.
