#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
雷池 滑块验证 / 浏览器验证            不知道是什么 浏览器验证还是5s盾   
=======================================
"""
import requests, re, sys, json
from urllib.parse import urlparse

URL = sys.argv[1] if len(sys.argv) > 1 else "目标"
PARSED = urlparse(URL)
ORIGIN = f"{PARSED.scheme}://{PARSED.netloc}"


def calc(data):
    #算法
    t, n, total = 1, len(data), sum(data)
    r = (6 + n + total) % 6 + 6
    for _ in range(r): t *= 6
    if t < 6666: t *= n
    if t > 0x3F940AA: t //= n
    for idx, val in enumerate(data):
        t += pow(val, 3); t ^= idx; t ^= val + idx
    result = []
    while t > 0: result.insert(0, t & 63); t >>= 6
    return result


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

print(f"目标: {URL}")

# 触发拦截 
r1 = s.get(ORIGIN, timeout=15)
print(f"绕过前: HTTP {r1.status_code} (468=被拦)")

m = re.search(r'SafeLineChallenge\("([^"]+)"', r1.text)
if not m: print("不是雷池 WAF"); sys.exit(1)
client_id = m.group(1)
print(f"client_id: {client_id}")

# 请求 PoW 数据
r2 = s.post(f"{ORIGIN}/.safeline/challenge/v2/api/issue",
            json={"client_id": client_id, "level": 1}, timeout=15)
d = r2.json()["data"]
print(f"issue_id: {d['issue_id']}")

# 计算
result = calc(d["data"])
print(f"result: {result}")

# 提交验证
r4 = s.post(f"{ORIGIN}/.safeline/challenge/v2/api/verify",
            json={"issue_id": d["issue_id"], "result": result, "serials": [],
                  "client": {"userAgent": "", "platform": "", "language": "", "vendor": "",
                             "screen": [0, 0], "visitorId": "", "score": 0, "target": []}},
            timeout=15)
jwt = r4.json()["data"]["jwt"]
print(f"verify: True  JWT: {jwt[:50]}...")

# cookie 重请求
s.cookies.set("sl-challenge-jwt", jwt, path="/")
s.cookies.set("sl-challenge-server", "local", path="/")

r5 = s.get(ORIGIN, timeout=15)
ok = r5.status_code != 468 and "SafeLineChallenge" not in r5.text
print(f"绕过后: HTTP {r5.status_code} [{'成功' if ok else '失败'}]")
if ok:
    print(f"HTML:\n{r5.text[:800]}")
