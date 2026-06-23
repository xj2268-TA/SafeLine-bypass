# SafeLine WAF绕过

雷池 SafeLine WAF 行为验证绕过，过滑动验证码和那个什么无感还是浏览器验证，不知道叫什么，
浏览器里效果：先弹出468验证页，脚本绕过，自动刷新变200展示正文。

## 用法

```bash
pip install requests urllib3 playwright
python -m playwright install chromium

python poc_safeline_bypass.py
```
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