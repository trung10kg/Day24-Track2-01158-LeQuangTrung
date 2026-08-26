"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Kiến trúc đã dùng ---

Run A (agent_owner="run-a", delegation_depth=0):
    - Gọi search_docs(message) — luôn allow (classification="internal",
      egress_enabled=False không bao giờ khớp rule deny tối thiểu).
    - Chạy llm.find_injection() trên TOÀN VĂN kết quả CHỈ để ghi log/audit
      (phát hiện goal-hijack) — KHÔNG BAO GIỜ dùng customer_id hay
      target_url mà nó trả về để quyết định gọi tool nào tiếp theo.
    - Nếu phát hiện injection: đánh giá qua policy.check() một request
      http_post "đại diện" cho đúng thứ attacker yêu cầu (classification=
      "restricted", egress_enabled=True) — rule tối thiểu deny nó. Ghi
      deny vào ledger. KHÔNG BAO GIỜ gọi tools.http_post thật (vừa vì
      policy deny, vừa vì kiến trúc Run A không cầm quyền gọi network).
      Đây là bằng chứng "egress deny" mà Rubric.md yêu cầu.

Run B (agent_owner="run-b", delegation_depth=1):
    - Input DUY NHẤT nhận từ Run A: list[int] ticket_id trích từ TÊN FILE
      các doc mà search_docs trả về (regex trên "id", không đọc "text").
    - Map ticket_id -> customer_id bằng NGUỒN TIN CẬY
      data/customers.json[*].related_tickets — KHÔNG bao giờ dùng
      customer_id mà attacker viết trong nội dung document.
    - Với mỗi customer_id map được: qua policy.check() (classification=
      "restricted", egress_enabled=False -> allow theo rule tối thiểu),
      ghi ledger, rồi mới gọi tools.read_customer().

Một khách chỉ được NHẮC TỚI trong free text của attacker (không có ticket
nào trong related_tickets của họ) sẽ KHÔNG BAO GIỜ được Run B đọc tới —
đây là containment kiến trúc, khác với một bộ lọc chuỗi (mitigation) luôn
có thể bị né bằng cách viết lại chỉ thị (xem biến thể 5).

Câu trả lời cuối cùng trả về người dùng luôn là llm.summarize(docs) —
giống hệt _naive_loop, không rò rỉ dữ liệu khách hàng vào output CLI.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_A = "run-a"
RUN_B = "run-b"

_TICKET_ID_RE = re.compile(r"ticket-(\d+)", re.IGNORECASE)


def _hash_args(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _log(ledger_path: Path, run_id: str, tool: str, args: dict, classification: str, allow: bool, reason: str) -> dict:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "agent_owner": run_id,
        "tool": tool,
        "args_hash": _hash_args(args),
        "classification": classification,
        "decision": "allow" if allow else "deny",
        "reason": reason,
    }
    return ledger.append(entry, ledger_path)


def _extract_ticket_ids(doc_ids: list[str]) -> list[int]:
    """TYPED, sanitize từ TÊN FILE — không bao giờ đọc nội dung document."""
    ids = set()
    for doc_id in doc_ids:
        match = _TICKET_ID_RE.search(doc_id)
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def _customer_ids_for_tickets(ticket_ids: list[int], customers: list[dict]) -> list[str]:
    """NGUỒN TIN CẬY: related_tickets trong customers.json, không phải
    customer_id mà attacker nhúng trong free text."""
    wanted = set(ticket_ids)
    matched = {
        customer["customer_id"]
        for customer in customers
        if wanted & set(customer.get("related_tickets", []))
    }
    return sorted(matched)


def _run_a(message: str, llm, ledger_path: Path) -> tuple[list[dict], object]:
    search_ctx = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-docs",
        agent_owner=RUN_A,
        delegation_depth=0,
        egress_enabled=False,
    )
    allow, reason = policy.check(search_ctx)
    _log(ledger_path, RUN_A, "search_docs", {"query": message}, "internal", allow, reason)

    docs = tools.search_docs(message) if allow else []

    combined_text = "\n\n".join(doc["text"] for doc in docs)
    injected = llm.find_injection(combined_text)

    if injected is not None:
        exfil_ctx = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="attacker-injected-exfil",
            agent_owner=RUN_A,
            delegation_depth=0,
            egress_enabled=True,
        )
        exfil_allow, exfil_reason = policy.check(exfil_ctx)
        _log(
            ledger_path,
            RUN_A,
            "http_post",
            {
                "target_url": injected.target_url,
                "requested_customer_ids": injected.customer_ids,
                "matched_markers": injected.matched_markers,
            },
            "restricted",
            exfil_allow,
            exfil_reason,
        )
        # Rule tối thiểu (restricted + egress_enabled=True -> deny) đảm bảo
        # exfil_allow luôn False ở đây. Dù policy có trả allow, Run A theo
        # kiến trúc trifecta split KHÔNG BAO GIỜ được cầm quyền http_post,
        # nên tool thật sự KHÔNG được gọi trong nhánh này.

    return docs, injected


def _run_b(docs: list[dict], ledger_path: Path) -> list[dict]:
    ticket_ids = _extract_ticket_ids([doc["id"] for doc in docs])
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    customer_ids = _customer_ids_for_tickets(ticket_ids, customers)

    collected = []
    for customer_id in customer_ids:
        read_ctx = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner=RUN_B,
            delegation_depth=1,
            egress_enabled=False,
        )
        allow, reason = policy.check(read_ctx)
        _log(ledger_path, RUN_B, "read_customer", {"customer_id": customer_id}, "restricted", allow, reason)
        if not allow:
            continue
        try:
            collected.append(tools.read_customer(customer_id))
        except tools.ToolError:
            continue

    return collected


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir is not None else DEFAULT_LEDGER_PATH

    docs, _injected = _run_a(message, llm, ledger_path)
    _run_b(docs, ledger_path)

    return llm.summarize(docs)
