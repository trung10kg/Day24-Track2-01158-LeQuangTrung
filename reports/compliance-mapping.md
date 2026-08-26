# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement (stretch goal #3 trong `Guide.md` — "Delete cascade: xoá 1 subject khỏi `customers.json`, giữ ledger nguyên vẹn"). Hiện tại `data/customers.json` không có cơ chế xoá subject theo yêu cầu; `reports/ledger.jsonl` vẫn giữ audit trail nếu có xoá trong tương lai (thiết kế append-only sẵn sàng cho việc này). | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM API call | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | Per-agent/per-run identity trên mọi tool call, đi qua PEP trước khi execute | `agent/policy.py:39-51` (`check()`); `agent/runner.py:90-102` (`_log`, gắn `agent_id`/`run_id`/`agent_owner` vào mọi entry); `reports/ledger.jsonl` mọi dòng đều có `agent_id="lab24-agent"`, `run_id`, `agent_owner` (ví dụ dòng 1: `run_id="run-a"`, dòng 3: `run_id="run-b"`). **Giới hạn:** chưa có TTL/expiry cho identity — đây là gap, không phải đã làm. |
| ASI01 — goal hijack | Trifecta split: Run A (search_docs, không cầm read_customer/http_post) tách khỏi Run B (read_customer, chỉ nhận `ticket_id: list[int]` đã sanitize từ tên file, không đọc free text) | `agent/runner.py:127-196` (`_run_a`, `_run_b`); minh chứng hiệu quả: `reports/attack-after.log`, `injection-corpus.md` (5/5 biến thể bị chặn), `tests/test_split.py` (PASSED — khách `KH-000777` chỉ được attacker nhắc trong free text không bao giờ bị `read_customer` gọi tới) |
| ISO 42001 Clause 5-6 | Policy-as-code có review qua git history, tách riêng theo từng thay đổi | `git log -- agent/policy.py` (mỗi thay đổi rule là 1 commit riêng, xem lịch sử commit của repo này) |

## Ghi chú minh bạch (không có trong bảng gốc nhưng liên quan trực tiếp)

- Rule tối thiểu bắt buộc theo `Guide.md` §3b (`classification == "restricted"
  and egress_enabled is True -> DENY`) được implement nguyên văn tại
  `agent/policy.py:40-45`, không có rule nào yếu hơn nó.
- Egress deny có bằng chứng thật (không chỉ file config): `reports/ledger.jsonl`
  dòng 2 (chạy Bước 4 lúc 2026-08-26T08:00:36Z) có
  `"tool": "http_post", "decision": "deny"` với `reason` non-empty, sinh ra
  từ một lần Run A thật sự đánh giá policy cho request egress mà chỉ thị
  injection yêu cầu — không phải giả lập trong tài liệu.
- Audit completeness: `agent/ledger.py:verify()` được test bởi
  `tests/test_ledger.py` (bao gồm test tamper — sửa 1 ký tự giữa file làm
  `verify()` trả `False`) và đã chạy tay trên `reports/ledger.jsonl` thật,
  kết quả `True` (xem `reports/attack-after.log`).
