import os
import sys
from flask import Flask, request, abort
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage

# 讓 app.py 可以 import 專案根目錄的 gmail_read.py
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from gmail_read import get_netflix_otp  # 確保 gmail_read.py 真的有這個函式

app = Flask(__name__)

@app.get("/")
def health():
    return "OK", 200


# ✅ 一定要先讀環境變數
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN")
LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET")

if not LINE_CHANNEL_ACCESS_TOKEN or not LINE_CHANNEL_SECRET:
    raise RuntimeError("請先設定環境變數 LINE_CHANNEL_ACCESS_TOKEN 與 LINE_CHANNEL_SECRET")

# ✅ 一定要先建立這兩個物件，才能用 @handler.add
line_bot_api = LineBotApi(LINE_CHANNEL_ACCESS_TOKEN)
handler = WebhookHandler(LINE_CHANNEL_SECRET)


@app.route("/callback", methods=["POST"])
def callback():
    signature = request.headers.get("X-Line-Signature", "")
    body = request.get_data(as_text=True)

    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)

    return "OK"


@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    text = (event.message.text or "").strip()

    # ✅ 群組輸入：驗證碼 -> 回 Netflix 4 碼
    if text == "驗證碼":
        otp = get_netflix_otp()
        if otp:
            reply = f"Netflix 驗證碼：{otp}"
        else:
            reply = "找不到最新的 Netflix 4 碼驗證碼（或信件還沒到）"

        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply))
        return

    # 其他訊息不回（避免吵群）
    return


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)


