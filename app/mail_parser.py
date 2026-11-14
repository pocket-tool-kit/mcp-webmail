from __future__ import annotations

import json
import re
from datetime import timezone
from email import policy
from email.header import Header, decode_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser

# Bump when parsing output changes; Database.initialize() rebuilds the cache.
PARSER_VERSION = 2

_ESC_JIS = (b"\x1b$", b"\x1b(")
# Labels whose C1 bytes (0x80-0x9F) are never real text; such bytes indicate a
# mislabelled Japanese/UTF-8 body. windows-1252 is excluded: C1 is text there.
_LATIN1_LABELS = {"iso-8859-1", "iso8859-1", "latin1", "latin-1", "l1", "us-ascii", "ascii"}
_ALIASES = {"shift_jis": "cp932", "shift-jis": "cp932", "sjis": "cp932", "x-sjis": "cp932",
            "ms_kanji": "cp932", "windows-31j": "cp932", "unknown-8bit": None, "x-unknown": None}


def _jis_to_cp932(value: bytes) -> str:
    """Decode ISO-2022-JP as CP50220 does: JIS X 0208 plus NEC/IBM extensions.

    Python's iso-2022-jp rejects row 13 (①, ㈱ ...) commonly sent by Outlook and
    Japanese webmail. Converting JIS rows to Shift_JIS and decoding with cp932
    covers those characters. Unknown designations raise UnicodeError.
    """
    out = bytearray()
    mode, i, n = "ascii", 0, len(value)
    while i < n:
        if value[i] == 0x1B:
            seq = value[i:i + 3]
            if seq in (b"\x1b$B", b"\x1b$@"):
                mode = "jis"
            elif seq in (b"\x1b(B", b"\x1b(J"):
                mode = "ascii"
            elif seq == b"\x1b(I":
                mode = "kana"
            else:
                raise UnicodeError("unsupported ISO-2022-JP designation")
            i += 3
            continue
        byte = value[i]
        if byte == 0x0E:  # SO: half-width katakana shift
            mode, i = "kana", i + 1
            continue
        if byte == 0x0F:
            mode, i = "ascii", i + 1
            continue
        if mode == "jis":
            if byte in (0x0A, 0x0D):  # tolerate missing reset before line end
                out.append(byte)
                i += 1
                continue
            if i + 1 >= n:
                raise UnicodeError("truncated JIS sequence")
            j1, j2 = byte, value[i + 1]
            if not (0x21 <= j1 <= 0x7E and 0x21 <= j2 <= 0x7E):
                raise UnicodeError("invalid JIS sequence")
            s1 = ((j1 - 0x21) >> 1) + 0x81
            if s1 > 0x9F:
                s1 += 0x40
            if j1 % 2:
                s2 = j2 + 0x1F + (1 if j2 >= 0x60 else 0)
            else:
                s2 = j2 + 0x7E
            out += bytes((s1, s2))
            i += 2
        elif mode == "kana":
            if 0x21 <= byte <= 0x5F:
                out.append(byte + 0x80)
            elif byte in (0x0A, 0x0D, 0x20):
                out.append(byte)
            else:
                raise UnicodeError("invalid JIS X 0201 kana")
            i += 1
        else:
            if byte > 0x7F:
                raise UnicodeError("8-bit byte in ISO-2022-JP")
            out.append(byte)
            i += 1
    return out.decode("cp932")


def _normalize(charset):
    if not charset:
        return None
    label = str(charset).strip().strip('"').lower()
    return _ALIASES.get(label, label)


def decode_bytes(value: bytes, charset: str | None = None) -> str:
    label = _normalize(charset)
    candidates: list = []
    has_esc = any(marker in value for marker in _ESC_JIS)
    if has_esc or (label and label.replace("_", "-").startswith("iso-2022-jp")):
        # Escape sequences are a stronger hint than an incorrect declaration.
        candidates += ["iso-2022-jp", _jis_to_cp932]
    if label and not (label in _LATIN1_LABELS and any(0x80 <= b <= 0x9F for b in value)):
        candidates.append(label)
    # EUC-JP before cp932: EUC bytes usually also decode as cp932 half-width
    # kana, while real Shift_JIS lead bytes (0x81-0x9F) are invalid in EUC-JP.
    candidates += ["utf-8", "euc_jp", "cp932"]
    for candidate in candidates:
        try:
            text = candidate(value) if callable(candidate) else value.decode(candidate)
        except (UnicodeError, LookupError):
            continue
        if has_esc and "\x1b" in text:
            continue  # undecoded JIS escapes are mojibake, not text
        return text
    return value.decode("utf-8", errors="replace")


def raw_header_text(value) -> str:
    """Header text without RFC 2047 decoding; raw 8-bit bytes are charset-guessed."""
    if value is None:
        return ""
    if isinstance(value, Header):
        # compat32 wraps raw 8-bit headers as unknown-8bit Header objects; their
        # chunks still hold the original bytes.
        try:
            return "".join(decode_bytes(v, enc) if isinstance(v, bytes) else v
                           for v, enc in decode_header(value))
        except Exception:
            return str(value)
    return str(value)


def header(value) -> str:
    text = raw_header_text(value)
    if "=?" not in text or not text.isascii():
        # decode_header() mangles non-ASCII text mixed with encoded-words.
        return text
    try:
        return "".join(decode_bytes(v, enc) if isinstance(v, bytes) else v
                       for v, enc in decode_header(text))
    except Exception:
        return text


def parse_recipients(msg) -> list[dict]:
    """Single source of truth for To/Cc/Bcc, used for display AND for sending.

    Addresses are parsed from the raw header before RFC 2047 decoding, so an
    encoded display name can never turn into an extra visible/hidden address.
    """
    recipients = []
    for kind in ("To", "Cc", "Bcc"):
        values = [raw_header_text(v) for v in msg.get_all(kind, [])]
        for name, address in getaddresses(values):
            if address:
                recipients.append({"type": kind.lower(), "name": header(name), "address": address})
    return recipients


class PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "head"}:
            self.hidden += 1
        if tag in {"p", "div", "br", "li", "tr"} and not self.hidden:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "head"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def html_to_text(value: str) -> str:
    parser = PlainHTML()
    try:
        parser.feed(value)
        return "".join(parser.parts).strip()
    except Exception:
        return re.sub(r"<[^>]*>", " ", value)


def parse_message(raw: bytes):
    # compat32 preserves undecoded raw header bytes for legacy Japanese mail.
    return BytesParser(policy=policy.compat32).parsebytes(raw)


def parse_mail(raw: bytes) -> dict:
    msg = parse_message(raw)
    text, html = [], []
    attached = False

    def visit(part):
        nonlocal attached
        if part.get_content_disposition() == "attachment" or part.get_filename():
            attached = True
            return
        if part.get_content_type() == "message/rfc822":
            attached = True
            return
        if part.is_multipart():
            for child in part.get_payload():
                visit(child)
            return
        kind = part.get_content_type()
        if kind not in {"text/plain", "text/html"}:
            attached = True
            return
        payload = part.get_payload(decode=True)
        value = decode_bytes(payload, part.get_content_charset()) if isinstance(payload, bytes) else str(part.get_payload())
        (html if kind == "text/html" else text).append(value)

    visit(msg)
    body_html = "\n".join(html)
    body_text = "\n".join(text) or html_to_text(body_html)
    try:
        date = parsedate_to_datetime(str(msg.get("Date", "")))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        date_ts = int(date.timestamp())
    except (ValueError, TypeError, OverflowError, IndexError):
        date_ts = 0
    return {
        "message_id": header(msg.get("Message-ID")).strip(),
        "in_reply_to": header(msg.get("In-Reply-To")).strip(),
        "references_header": header(msg.get("References")),
        "subject": header(msg.get("Subject")), "sender": header(msg.get("From")),
        "reply_to": header(msg.get("Reply-To")),
        "recipients": json.dumps(parse_recipients(msg), ensure_ascii=False), "date_ts": date_ts,
        "body_text": body_text, "body_html": body_html, "has_attachments": attached,
    }


def placeholder(subject: str, body: str, **extra) -> dict:
    mail = parse_mail(f"Subject: {subject}\r\n\r\n{body}".encode("ascii"))
    mail.update(extra)
    return mail
