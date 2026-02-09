import os
import re
import base64
from typing import Optional, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
NETFLIX_SENDER = "info@account.netflix.com"


def extract_otp(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"\b(\d{4})\b", text)
    return m.group(1) if m else None


def decode_base64url(data: str) -> str:
    """
    Gmail API 會回 base64url，常缺 padding，必須補 '='
    """
    if not data:
        return ""
    missing = len(data) % 4
    if missing:
        data += "=" * (4 - missing)
    return base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="ignore")


def get_text_from_payload(payload: dict) -> str:
    """
    同時支援：
    - payload.body.data
    - payload.parts (包含多層巢狀)
    """
    texts = []

    if not payload:
        return ""

    # 1) payload 本身就有 body.data
    mime0 = payload.get("mimeType", "")
    data0 = (payload.get("body") or {}).get("data")
    if data0 and mime0 in ("text/plain", "text/html"):
        texts.append(decode_base64url(data0))

    # 2) parts 遞迴
    def walk(parts):
        for p in parts or []:
            mime = p.get("mimeType", "")
            data = (p.get("body") or {}).get("data")
            if data and mime in ("text/plain", "text/html"):
                texts.append(decode_base64url(data))
            if p.get("parts"):
                walk(p.get("parts"))

    walk(payload.get("parts", []))
    return "\n".join([t for t in texts if t]).strip()


def get_gmail_service():
    # ✅ 跟你 Render env 的 key 一致
    client_id = os.environ.get("GMAIL_CLIENT_ID")
    client_secret = os.environ.get("GMAIL_CLIENT_SECRET")
    refresh_token = os.environ.get("GMAIL_REFRESH_TOKEN")

    missing = [k for k, v in [
        ("GMAIL_CLIENT_ID", client_id),
        ("GMAIL_CLIENT_SECRET", client_secret),
        ("GMAIL_REFRESH_TOKEN", refresh_token),
    ] if not v]
    if missing:
        raise RuntimeError(f"Missing env vars: {', '.join(missing)}")

    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )
    creds.refresh(Request())
    return build("gmail", "v1", credentials=creds)


def find_latest_netflix_otp(max_results: int = 10) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    service = get_gmail_service()

    # 加上時間限制避免撈到很舊的信
    query = f"from:({NETFLIX_SENDER}) newer_than:2d"

    results = service.users().messages().list(
        userId="me", q=query, maxResults=max_results
    ).execute()

    for msg in results.get("messages", []) or []:
        msg_id = msg["id"]

        full = service.users().messages().get(
            userId="me", id=msg_id, format="full"
        ).execute()

        headers = (full.get("payload") or {}).get("headers", []) or []
        hmap = {h.get("name", ""): h.get("value", "") for h in headers}
        subject = hmap.get("Subject", "") or ""
        from_ = hmap.get("From", "") or ""

        # 先從標題找
        otp = extract_otp(subject)
        if otp:
            return otp, from_, subject

        # 再從內文找
        text = get_text_from_payload(full.get("payload") or {})
        otp = extract_otp(text)
        if otp:
            return otp, from_, subject

    return None, None, None


def get_netflix_otp() -> Optional[str]:
    """
    給 app.py 呼叫：不讓 HttpError 直接把 LINE bot 打爆
    """
    try:
        otp, _, _ = find_latest_netflix_otp()
        return otp
    except HttpError as e:
        # Render -> Logs 會看到真正原因（401/403/400）
        print("❌ Gmail API HttpError:", str(e))
        return None
    except Exception as e:
        print("❌ Gmail read error:", repr(e))
        return None
