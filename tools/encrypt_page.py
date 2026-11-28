#!/usr/bin/env python3
"""cheers-share の鍵付きページを作る。

使い方: python3 tools/encrypt_page.py <フォルダ名> <元のHTML> [--key 鍵]
  - 元のHTMLが <!doctype で始まらなければ、charset・viewport・リセットの土台を付ける
  - <フォルダ名>/index.html に暗号化した入れ物を書く（鍵＝URLの # のあと）
  - 鍵を省くと、同じフォルダの既存の鍵がわからないため新しく作る（リンクが変わる）
鍵の作り方: SHA-256("cm-share:" + フォルダ名 + ":" + 鍵) を AES-GCM の鍵にする（既存ページと同じ）。
"""
import argparse, base64, hashlib, json, os, secrets, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = ('<!doctype html><html lang="ja"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
        '<meta name="robots" content="noindex,nofollow"><style>:root{color-scheme:light;'
        'padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}'
        'body{margin:0;font-family:system-ui,sans-serif;font-size:14px}img{max-width:100%}'
        '[hidden]{display:none!important}</style></head><body>\n')

WRAP = '''<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>チアーズメイト</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fff;color:#333;
  font-family:"Hiragino Sans","Yu Gothic",sans-serif;font-size:16px;line-height:1.8;text-align:center;padding:16px;box-sizing:border-box}
</style>
</head>
<body>
<p id="msg">読み込んでいます</p>
<script id="box" type="application/json">@BOX@</script>
<script>
addEventListener("load", async () => {
  try {
    const box = JSON.parse(document.getElementById("box").textContent);
    const bytes = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("cm-share:" + box.s + ":" + location.hash.slice(1)));
    const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt({name: "AES-GCM", iv: bytes(box.n)}, key, bytes(box.c));
    document.open();
    document.write(new TextDecoder().decode(plain));
    document.close();
  } catch (e) {
    document.getElementById("msg").textContent = "このページは、案内されたリンクから開いてください。";
  }
});
</script>
</body>
</html>
'''

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder"); ap.add_argument("src"); ap.add_argument("--key")
    a = ap.parse_args()
    html = open(a.src, encoding="utf-8").read()
    if not html.lstrip().lower().startswith("<!doctype"):
        html = BASE + html + "\n</body></html>\n"
    key = a.key or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")
    k = hashlib.sha256(f"cm-share:{a.folder}:{key}".encode()).digest()
    iv = secrets.token_bytes(12)
    ct = AESGCM(k).encrypt(iv, html.encode("utf-8"), None)
    box = json.dumps({"s": a.folder, "n": base64.b64encode(iv).decode(), "c": base64.b64encode(ct).decode()})
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(root, a.folder), exist_ok=True)
    open(os.path.join(root, a.folder, "index.html"), "w", encoding="utf-8").write(WRAP.replace("@BOX@", box))
    print(f"https://auscheersmate11-afk.github.io/cheers-share/{a.folder}/#{key}")

if __name__ == "__main__":
    main()
