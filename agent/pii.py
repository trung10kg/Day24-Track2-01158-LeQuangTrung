"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt sẵn
(AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re
import unicodedata

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DIGIT_RUN_RE = re.compile(r"\d+")

# Cửa sổ ký tự trước một dãy số dùng để phân biệt STK/CCCD khi độ dài
# trùng nhau (đúng 12 chữ số) — xem scripts/generate_fixtures.py:
# random_bank_account() có thể ra 12 chữ số, cùng độ dài với CCCD, nên
# chỉ dựa vào length là không đủ.
_CONTEXT_WINDOW = 25
_BANK_CONTEXT_HINTS = ("stk", "tai khoan")


def _strip_diacritics(text: str) -> str:
    text = text.replace("đ", "d").replace("Đ", "D")
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


def _classify_digit_run(text: str, start: int, end: int) -> str | None:
    digits = text[start:end]
    length = len(digits)

    if length == 12:
        context = _strip_diacritics(text[max(0, start - _CONTEXT_WINDOW) : start])
        if any(hint in context for hint in _BANK_CONTEXT_HINTS):
            return "VN_BANK_ACCOUNT"
        return "VN_CCCD"
    if digits[0] == "0" and length in (10, 11):
        return "VN_PHONE"
    if 8 <= length <= 16:
        return "VN_BANK_ACCOUNT"
    return None


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    claimed: list[tuple[int, int]] = []

    for match in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": match.start(), "end": match.end()})
        claimed.append((match.start(), match.end()))

    for match in _DIGIT_RUN_RE.finditer(text):
        start, end = match.start(), match.end()
        if any(start < c_end and c_start < end for c_start, c_end in claimed):
            continue
        entity_type = _classify_digit_run(text, start, end)
        if entity_type is None:
            continue
        entities.append({"type": entity_type, "start": start, "end": end})
        claimed.append((start, end))

    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    entities = sorted(detect(text), key=lambda e: e["start"], reverse=True)
    for entity in entities:
        placeholder = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + placeholder + text[entity["end"] :]
    return text
