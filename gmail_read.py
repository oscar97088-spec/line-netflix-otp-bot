# gmail_read.py
import os
import re
import base64
from typing import Optional, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def _env(*names: str) -> str:
    """依序找環境變數，找不到就丟出清楚錯誤訊息。"""
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    raise KeyError(f"Missing env var. Tried: {', '.join(names)}")


def get_gmail_service():
    """
    Render/Server 用 refresh token 取得 Gmail service（不依賴任何 json 檔）
    支援兩套 env 名稱：
      - GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN
      - GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN
    """
    client_id = _env("GMAIL_CLIENT_ID", "GOOGLE_CLIENT_ID")
    client_secret = _env("GMAIL_CLIENT_SECRET", "GOOGLE_CLIENT_SECRET")
    refresh_token = _env("GMAIL_REFRESH_TOKEN", "GOOGLE_REFRESH_TOKEN")

    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )

    # 用 refresh token 換 access token
    creds.refresh(Request())
    return build("gmail", "v1", credentials=creds)


def extract_otp(text: str) -> Optional[str]:
    """抓 4 碼 OTP（取第一個）"""
    if not text:
        return None
    m = re.search(r"\b\d{4}\b", text)
    return m.group(0) if m else None


def decode_base64url(data: str) -> str:
    if not data:
        return ""
    return base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="ignore")


def get_text_from_payload(payload: dict) -> str:
    """盡量把 email 內容（text/plain 優先）抽出來。"""
    if not payload:
        return ""

    body = payload.get("body", {})
    data = body.get("data")
    if data:
        return decode_base64url(data)

    parts = payload.get("parts", [])
    texts = []

    def walk(parts_list):
        for p in parts_list:
            mime = p.get("mimeType", "")
            b = p.get("body", {})
            d = b.get("data")

            if mime == "text/plain" and d:
                texts.append(decode_base64url(d))
            elif mime == "text/html" and d:
                texts.append(decode_base64url(d))

            if p.get("parts"):
                walk(p["parts"])

    walk(parts)
    return "\n".join(t for t in texts if t).strip()


def find_latest_netflix_otp(max_results: int = 10) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    回傳 (otp, from_, subject)
    找不到就回 (None, None, None)
    """
    service = get_gmail_service()

    # Netflix 常見寄件人（你也可以再加）
    query = "from:(info@account.netflix.com)"

    results = service.users().messages().list(
        userId="me",
        q=query,
        maxResults=max_results
    ).execute()

    messages = results.get("messages", [])
    if not messages:
        return None, None, None

    for msg in messages:
        msg_id = msg["id"]

        # 先用 metadata 快速抓 Subject
        meta = service.users().messages().get(
            userId="me",
            id=msg_id,
            format="metadata",
            metadataHeaders=["From", "Subject"]
        ).execute()

        headers = meta.get("payload", {}).get("headers", [])
        hmap = {h.get("name", ""): h.get("value", "") for h in headers}
        from_ = hmap.get("From", "")
        subject = hmap.get("Subject", "")

        otp = extract_otp(subject)
        if otp:
            return otp, from_, subject

        # Subject 沒找到就抓全文
        full = service.users().messages().get(
            userId="me",
            id=msg_id,
            format="full"
        ).execute()

        payload = full.get("payload", {})
        text = get_text_from_payload(payload)

        otp = extract_otp(text)
        if otp:
            return otp, from_, subject

    return None, None, None


def get_netflix_otp() -> Optional[str]:
    """給 LINE Bot 用：只回 OTP，找不到回 None"""
    otp, _, _ = find_latest_netflix_otp()
    return otp


if __name__ == "__main__":
    otp, from_, subject = find_latest_netflix_otp()
    print("From:", from_)
    print("Subject:", subject)
    print("OTP:", otp)
