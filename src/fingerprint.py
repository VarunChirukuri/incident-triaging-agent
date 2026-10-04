import re, hashlib
from typing import Optional

UUID_REGEX = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX_ADDR_REGEX = re.compile(r"0x[0-9a-fA-F]+")
TIMESTAMP_REGEX = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?")
IP_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
NUMERIC_ID_REGEX = re.compile(r"\b(id|user|order|txn|item)[=:_ ]\s*\d+\b", re.IGNORECASE)
INT_LITERAL_REGEX = re.compile(r"\b\d{5,}\b")

class ErrorFingerprinter:
    @staticmethod
    def normalize_message(message: str) -> str:
        if not message:
            return ""
        norm = UUID_REGEX.sub("<UUID>", message)
        norm = HEX_ADDR_REGEX.sub("<ADDR>", norm)
        norm = TIMESTAMP_REGEX.sub("<TIMESTAMP>", norm)
        norm = IP_REGEX.sub("<IP>", norm)
        norm = NUMERIC_ID_REGEX.sub(r"\1=<ID>", norm)
        norm = INT_LITERAL_REGEX.sub("<NUM>", norm)
        norm = re.sub(r"\s+", " ", norm).strip()
        return norm

    @classmethod
    def extract_top_stack_frame(cls, stack_trace: Optional[str]) -> str:
        if not stack_trace:
            return ""
        lines = [line.strip() for line in stack_trace.strip().splitlines() if line.strip()]
        for line in reversed(lines):
            if "File " in line or line.startswith("at ") or line.startswith("in "):
                return cls.normalize_message(line)
        return cls.normalize_message(lines[-1]) if lines else ""

    @classmethod
    def compute_signature(cls, service: str, title: str, message: str, stack_trace: Optional[str] = None) -> str:
        norm_title = cls.normalize_message(title)
        norm_msg = cls.normalize_message(message)
        top_frame = cls.extract_top_stack_frame(stack_trace)
        raw_key = f"{service.lower()}|{norm_title}|{norm_msg}|{top_frame}"
        hasher = hashlib.sha256(raw_key.encode("utf-8"))
        return f"SIG-{hasher.hexdigest()[:12].upper()}"
