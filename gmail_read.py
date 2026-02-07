# gmail_read.py
import os
import re
import base64
from typing import Optional, Tuple

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def extract_otp(text: str) -> Optional[str]:
    """從文字中抓 4 碼 OTP（只取第一個）"""
    if not text:
        return None
    m = re.search(r"\b\d{4}\b", text)
    return m.group(0) if m else None


def decode_base64url(data: str) -> str:
    """Gmail API 回傳的 body.data 是 base64url，需要 decode。"""
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


def get_gmail_service():
    """
    ✅ Render/雲端專用：用環境變數建立 Gmail API 憑證
    需要在 Render 設定：
      - GOOGLE_CLIENT_ID
      - GOOGLE_CLIENT_SECRET
      - GOOGLE_REFRESH_TOKEN
    """
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    refresh_token = os.getenv("GOOGLE_REFRESH_TOKEN")

    if not client_id or not client_secret or not refresh_token:
        raise RuntimeError(
            "Missing env vars: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN"
        )

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


def find_latest_netflix_otp(max_results: int = 10) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    回傳 (otp, from_, subject)
    找不到就回傳 (None, None, None)

    只抓 Netflix 寄件人：info@account.netflix.com
    OTP 只抓「4 碼」
    """
    service = get_gmail_service()
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
    """只回傳 OTP（找不到回 None），給 LINE Bot 用"""
    otp, _, _ = find_latest_netflix_otp()
    return otp


def main():
    otp, from_, subject = find_latest_netflix_otp()
    if not otp:
        print("找不到 Netflix 的 4 碼驗證碼（寄件人 info@account.netflix.com）。")
        return

    print("✅ From:", from_)
    print("✅ Subject:", subject)
    print("🎯 Netflix 驗證碼：", otp)


if __name__ == "__main__":
    main()
