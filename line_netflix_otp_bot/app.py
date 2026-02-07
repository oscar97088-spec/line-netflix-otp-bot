# gmail_read.py
import os
import re
import base64
from typing import Optional, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# 只讀 Gmail
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

NETFLIX_SENDER = "info@account.netflix.com"


# -------------------------
# 工具函式
# -------------------------
def extract_otp(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"\b\d{4}\b", text)
    return m.group(0) if m else None


def decode_base64url(data: str) -> str:
    if not data:
        return ""
    return base64.urlsafe_b64decode(data.encode("utf-8")).decode(
        "utf-8", errors="ignore"
    )


def get_text_from_payload(payload: dict) -> str:
    if not payload:
        return ""

    body = payload.get("body", {})
    if body.get("data"):
        return decode_base64url(body["data"])

    texts = []

    def walk(parts):
        for p in parts:
            mime = p.get("mimeType", "")
            data = p.get("body", {}).get("data")

            if data and mime in ("text/plain", "text/html"):
                texts.append(decode_base64url(data))

            if p.get("parts"):
                walk(p["parts"])

    walk(payload.get("parts", []))
    return "\n".join(texts).strip()


# -------------------------
# Gmail Service（關鍵）
# -------------------------
def get_gmail_service():
    """
    ❗ Render / 雲端專用
    使用 refresh token，不用任何 json 檔
    """
    creds = Credentials(
        token=None,
        refresh_token=os.environ["GOOGLE_REFRESH_TOKEN"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        scopes=SCOPES,
    )

    # 取得 access token
    creds.refresh(Request())

    return build("gmail", "v1", credentials=creds)


# -------------------------
# 主要邏輯
# -------------------------
def find_latest_netflix_otp(
    max_results: int = 10,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    service = get_gmail_service()

    results = (
        service.users()
        .messages()
        .list(
            userId="me",
            q=f"from:({NETFLIX_SENDER})",
            maxResults=max_results,
        )
        .execute()
    )

    messages = results.get("messages", [])
    if not messages:
        return None, None, None

    for msg in messages:
        msg_id = msg["id"]

        meta = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=msg_id,
                format="metadata",
                metadataHeaders=["From", "Subject"],
            )
            .execute()
        )

        headers = meta.get("payload", {}).get("headers", [])
        h = {x["name"]: x["value"] for x in headers}
        from_ = h.get("From", "")
        subject = h.get("Subject", "")

        otp = extract_otp(subject)
        if otp:
            return otp, from_, subject

        full = (
            service.users()
            .messages()
            .get(userId="me", id=msg_id, format="full")
            .execute()
        )

        text = get_text_from_payload(full.get("payload", {}))
        otp = extract_otp(text)
        if otp:
            return otp, from_, subject

    return None, None, None


def get_netflix_otp() -> Optional[str]:
    otp, _, _ = find_latest_netflix_otp()
    return otp
