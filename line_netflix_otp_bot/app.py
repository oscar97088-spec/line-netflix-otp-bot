import os
from flask import Flask, request, abort

from linebot.v3.webhook import WebhookHandler
from linebot.v3.webhooks import MessageEvent, TextMessageContent
from linebot.v3.messaging import (
    Configuration, ApiClient, MessagingApi,
    ReplyMessageRequest, TextMessage
)
from linebot.v3.exceptions import InvalidSignatureError

from gmail_read import get_netflix_otp  # ✅ 從 repo 根目錄匯入

app = Flask(__name__)

LINE_CHANNEL_ACCESS_TOKEN = os.environ["LINE_CHANNEL_ACCESS_TOKEN"]
LINE_CHANNEL_SECRET = os.environ["LINE_CHANNEL_SECRET"]

handler = WebhookHandler(LINE_CHANNEL_SECRET)
configuration = Configuration(access_token=LINE_CHANNEL_ACCESS_TOKEN)


# Render health check
@app.get("/")
def health():
    return "OK", 200


@app.post("/callback")
def callback():
    signature = request.headers.get("X-Line-Signature", "")
    body = request.get_data(as_text=True)

    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)

    return "OK", 200


@handler.add(MessageEvent, message=TextMessageContent)
def handle_message(event):
    text = (event.message.text or "").strip()

    if text != "驗證碼":
        return

    try:
        otp = get_netflix_otp()
        if otp:
            reply_text = f"Netflix 驗證碼：{otp}"
        else:
            reply_text = "目前找不到 Netflix 驗證碼（信可能還沒到）。"
    except Exception as e:
        # ⭐ 超重要：避免 Gmail 出錯直接炸掉整個服務
        reply_text = f"系統錯誤：{type(e).__name__}"

    with ApiClient(configuration) as api_client:
        line_api = MessagingApi(api_client)
        line_api.reply_message(
            ReplyMessageRequest(
                reply_token=event.reply_token,
                messages=[TextMessage(text=reply_text)]
            )
        )

# ❌ 不要有 app.run()
