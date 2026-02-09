import os
import re
import base64
from typing import Optional, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# =========================
# 基本設定
# =========================
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
NETFLIX_SENDER = "info@account.netflix.com"


# =========================
# OTP 擷取（只抓 4 位數）
# =========================
def extract_otp(text: str) -> Optional[str]:
    """
    只擷取 4 位數驗證碼
    """
    if not text:
        return None

    match = re.search(r"\b\d{4}\b", text)
    return match.group(0) if match else None


# =========================
# Gmail 內容解析
# =========================
def decode_base64url(data: str) -> str:
    if not data:
        return ""
    return base64.urlsafe_b64decode(data.encode()).decode(errors="ignore")


def get_text_from_payload(payload: dict) -> str:
    """
    遞迴解析 Gmail payload，抓出所有 text/plain / text/html
    """
    texts = []

    def walk(parts):
        for part in parts:
            mime_type = part.get("mimeType", "")
            body = part.get("body", {})
            data = body.get("data")

            if data and mime_type in ("text/plain", "text/html"):
                texts.append(decode_base64url(data))

            if "parts" in part:
                walk(part["parts"])

    if "parts" in payload:
        walk(payload["parts"])

    return "\n".join(texts)


# =========================
# Gmail API 連線
# =========================
def get_gmail_service():
    creds = Credentials(
        token=None,
        refresh_token=os.environ.get("GMAIL_REFRESH_TOKEN"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ.get("GMAIL_CLIENT_ID"),
        client_secret=os.environ.get("GMAIL_CLIENT_SECRET"),
        scopes=SCOPES,
    )

    creds.refresh(Request())
    return build("gmail", "v1", credentials=creds)


# =========================
# 尋找最新 Netflix 驗證碼
# =========================
def find_latest_netflix_otp(
    max_results: int = 10,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    service = get_gmail_service()

    query = f"from:({NETFLIX_SENDER})"
    results = (
        service.users()
        .messages()
        .list(userId="me", q=query, maxResults=max_results)
        .execute()
    )

    for msg in results.get("messages", []):
        msg_id = msg["id"]

        full_message = (
            service.users()
            .messages()
            .get(userId="me", id=msg_id, format="full")
            .execute()
        )

        payload = full_message.get("payload", {})
        headers = payload.get("headers", [])

        header_map = {h["name"]: h["value"] for h in headers}
        subject = header_map.get("Subject", "")
        from_addr = header_map.get("From", "")

        # 1️⃣ 先從標題抓
        otp = extract_otp(subject)
        if otp:
            return otp, from_addr, subject

        # 2️⃣ 再從內文抓
        body_text = get_text_from_payload(payload)
        otp = extract_otp(body_text)
        if otp:
            return otp, from_addr, subject

    return None, None, None


# =========================
# 對外使用的主函式
# =========================
def get_netflix_otp() -> Optional[str]:
    otp, _, _ = find_latest_netflix_otp()
    return otp
