# sec-rate-limit：限流器为什么一点没限住

## 题面

撞库脚本换着 IP 打接口，限流阈值明明设了，峰值却一点没压下去：token_bucket 补给完没把 last 前移，同一个时间片被反复兑换成令牌，桶越用越满；token_bucket 不按 capacity 截断，空闲一会儿就能攒出无上限的突发额度；key_for 只认 IP，NAT 出口后的正常用户被并进同一个桶一起限流，攻击者轮换 IP 就换出一份新配额；key_for 不规范化 IPv6，::1 与 0:0:0:0:0:0:0:1 被当成两个键，换个写法就能刷新额度；allow 拒绝请求时也扣令牌，被打的键余额越扣越负，后续合法请求被长时间拒绝；consume 在余额不足时仍然扣掉一部分，计数器漂移、账实不符；refill 遇到时钟回拨返回负补给或直接补满，改本机时钟即可绕过限流；sliding_window 用固定窗口近似，窗口边界两侧各放行一批，峰值直接翻倍；validate_config 不检查容量与速率的量级关系，0<capacity<1 这种永远凑不齐 1 个令牌的配置照样通过，所有请求被永久拒绝；limit_batch 让所有键共用一个桶，键之间互相耗尽，攻击者用无关键就能打空别人的额度。ratelimit/bucket.py 是核心，tests/test_bucket.py 15个红。要修的是：上述 10 处令牌补给、限流键、原子扣减、滑动窗口与批量隔离缺陷，修到 `python -m pytest tests -q` 全绿（15 passed）。

## 运行方式

```bat
cd sec-rate-limit
python -m pytest tests -q
```

初始状态必须恰好是 `15 failed`（8 个函数全部 `raise NotImplementedError`，不允许出现
collection / import / syntax error）；把 `ratelimit/` 修好后应变成 `15 passed`。

单个用例调试：

```bat
python -m pytest tests/test_bucket.py -q -k token_bucket
python -m pytest "tests/test_bucket.py::test_capacity_boundary_allows_exactly_capacity" -q
```

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 文件结构

```
sec-rate-limit/
├── README.md
├── conftest.py            # 把仓库根目录加入 sys.path
├── .gitignore
├── ratelimit/
│   ├── __init__.py
│   └── bucket.py          # 8 个待实现函数（核心）
└── tests/
    └── test_bucket.py     # 15 个用例，不可修改
```

## 契约要点

- 时间一律是整毫秒（`int`），由调用方显式传入；不使用 `time.time()`，不等待真实时钟。
- 令牌是 `float`，比较使用绝对容差 `1e-9`，任何输出都不得为负。
- 限流器状态形如 `{"buckets": {key: {"tokens": float, "last": int}}}`；
  `allow` 必须原地更新它（用例会直接读 `state["buckets"]`）。
- 只允许 Python 标准库（`math`、`collections` 等）+ `pytest`：离线、不联网、不引入第三方包。
- 不使用随机数；同一输入必须得到同一结果。

## 约束

1. **`tests/` 不可修改**：不得增删用例、不得改断言或容差、不得跳过；只能改 `ratelimit/`。
2. 8 个函数的签名与 docstring 是验收契约，不要改签名。
3. `ratelimit/bucket.py` 的 docstring 里写明了每个函数的边界语义（左开右闭区间、
   回拨时 `last` 不前移、余额不足不扣减、键转义等），按契约实现即可。
