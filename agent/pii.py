"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
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


_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9_-])", re.I)
_DIGITS = re.compile(r"(?<!\d)\d{8,16}(?!\d)")
_PHONE = re.compile(r"(?<!\d)0(?:[\s-]?\d){9,10}(?!\d)")
_CCCD_LABEL = re.compile(r"\b(?:CCCD|căn\s*cước|can\s*cuoc)\b", re.I)
_BANK_LABEL = re.compile(r"\b(?:STK|số\s*tài\s*khoản|so\s*tai\s*khoan|bank[_ ]?account)\b", re.I)


def _near_label(text: str, start: int, pattern: re.Pattern[str]) -> bool:
    # The label must precede the value closely; punctuation and names may sit
    # between them, but a label for a previous number must not carry over.
    prefix = text[max(0, start - 40):start]
    return bool(pattern.search(prefix))


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    for match in _EMAIL.finditer(text):
        entities.append({"type": "EMAIL", "start": match.start(), "end": match.end()})

    for match in _DIGITS.finditer(text):
        value = match.group()
        if _near_label(text, match.start(), _BANK_LABEL):
            kind = "VN_BANK_ACCOUNT"
        elif len(value) == 12 and _near_label(text, match.start(), _CCCD_LABEL):
            kind = "VN_CCCD"
        elif value.startswith("0") and len(value) in (10, 11):
            kind = "VN_PHONE"
        elif len(value) == 12:
            kind = "VN_CCCD"
        else:
            kind = "VN_BANK_ACCOUNT"
        entities.append({"type": kind, "start": match.start(), "end": match.end()})

    occupied = [(entity["start"], entity["end"]) for entity in entities]
    for match in _PHONE.finditer(text):
        if not any(match.start() < end and start < match.end() for start, end in occupied):
            entities.append({"type": "VN_PHONE", "start": match.start(), "end": match.end()})

    return sorted(entities, key=lambda entity: (entity["start"], entity["end"]))


def redact(text: str) -> str:
    for entity in reversed(detect(text)):
        text = (text[:entity["start"]] + f"[REDACTED_{entity['type']}]"
                + text[entity["end"]:])
    return text
