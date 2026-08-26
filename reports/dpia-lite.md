# DPIA-lite (1 trang)

## 1. Dữ liệu gì

Agent chạm vào 2 nguồn dữ liệu riêng biệt, ứng với 2 tool khác nhau:

- **`search_docs` (corpus/*.md, 46 file):** nội dung ticket hỗ trợ khách
  hàng — tên khách, chủ đề khiếu nại, và trong 5 file `ticket-90N*.md`
  (biến thể injection) còn có `customer_id` dạng `KH-000999` do bên viết
  ticket (có thể là attacker) tự nhúng vào free text. Classification:
  `"internal"` (`agent/runner.py` — `_run_a`, `search_ctx`).
- **`read_customer` (data/customers.json, 26 khách hàng):** `customer_id`,
  `name` (họ tên), `cccd` (số CCCD — dữ liệu cá nhân nhạy cảm theo Luật
  91/2025), `phone`, `bank_account`, `email`, `related_tickets`.
  Classification: `"restricted"` (`agent/runner.py` — `_run_b`, `read_ctx`).
- **`agent/pii.py`** phát hiện 4 loại PII trong text tự do: `VN_CCCD`,
  `VN_PHONE`, `VN_BANK_ACCOUNT`, `EMAIL` — dùng để đo trên
  `tests/vn_pii_testset.jsonl` (recall/precision hiện tại: 100%/100%,
  xem `pytest tests/test_pii.py -v -s`). **Lưu ý:** `agent/pii.py` hiện
  CHƯA được gọi trong `agent/runner.py` để redact nội dung trước khi đưa
  vào `llm.summarize()` — vì `summarize()` (cả `MockLLM` và `RealLLM`)
  chỉ nhận `docs` (nội dung ticket), không nhận customer record, nên
  không có CCCD/STK/SĐT thật của khách hàng chảy vào bước này trong luồng
  hiện tại. Đây là điểm cần lưu ý nếu tương lai thêm tool đọc ticket có
  chứa PII khách hàng thật (không chỉ synthetic).

## 2. Mục đích gì

Agent trả lời yêu cầu "tổng hợp/đối soát ticket còn mở" của nhân viên hỗ
trợ. Việc đọc `read_customer` chỉ xảy ra khi có MỘT ticket thật (tên file
trong `corpus/`, không phải nội dung do ai đó viết) khớp với
`related_tickets` của khách hàng đó trong `data/customers.json` — tức
mục đích luôn là "xác minh danh tính cho ticket có thật", không phải
"tra cứu khách hàng theo yêu cầu tự do trong văn bản". Kết quả cuối cùng
trả về người dùng (`llm.summarize(docs)`) chỉ dựa trên nội dung ticket,
KHÔNG bao gồm CCCD/SĐT/STK/email của khách hàng — dữ liệu restricted chỉ
được đọc nội bộ trong Run B, không xuất hiện trong output.

## 3. Chảy đi đâu

- **Nội bộ, trong lab:** `corpus/*.md` → context của Run A (không rời máy
  cục bộ). `data/customers.json` → bộ nhớ của Run B (không rời máy cục
  bộ, không ghi ra `reports/ledger.jsonl` ở dạng thô — ledger chỉ lưu
  `args_hash` là SHA-256 của `{"customer_id": ...}`, xem
  `agent/runner.py:_hash_args`, không lưu CCCD/SĐT/STK/email).
- **Sink cục bộ (`localhost:9999`):** đích duy nhất `http_post` được phép
  gọi (`agent/tools.py` hard-allowlist). Trong lab, đây là điểm exfil giả
  lập — sau khi contain (Bước 3), mọi lần policy đánh giá một request
  `http_post` mang `classification="restricted"` đều bị DENY
  (`agent/policy.py:40-45`), nên dữ liệu khách hàng thật chưa từng chạm
  tới sink sau containment (bằng chứng: `reports/attack-after.log`,
  `reports/sink.log` rỗng, `pytest tests/test_injection.py -v` 5/5 pass).
- **Ra ngoài Internet / nước thứ ba (NĐ 356/2025):** CHỈ xảy ra khi chạy
  với `--model claude-...` (KHÔNG phải chế độ chấm điểm — Rubric.md chấm
  bằng `--mock`, hoàn toàn cục bộ, không có request mạng ra ngoài nào).
  Nếu dùng `--model`, `RealLLM.summarize()` (`agent/llm.py`) gửi TOÀN VĂN
  `docs` (nội dung ticket) tới Anthropic API — đây là chuyển dữ liệu
  xuyên biên giới. **Gap cần ghi nhận:** luồng này gửi `docs` nguyên văn,
  CHƯA qua `agent/pii.py` để redact trước khi gửi — nếu ticket chứa PII
  thật (không phải dữ liệu synthetic của lab), đây là rủi ro tuân thủ
  NĐ 356/2025 cần xử lý trước khi dùng ngoài môi trường lab (ví dụ: gọi
  `pii.redact()` trên từng `doc["text"]` trước khi truyền vào
  `RealLLM.summarize()`). `customer_id`/CCCD/STK từ `read_customer`
  KHÔNG bao giờ được truyền vào `summarize()` trong kiến trúc hiện tại,
  nên record khách hàng đầy đủ không đi qua đường này — chỉ nội dung
  ticket (có thể chứa PII do người viết ticket tự nhúng) mới có nguy cơ.
