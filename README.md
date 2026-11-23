# sec-rate-limit：限流器为什么一点没限住

## 题面

撞库脚本换着 IP 打接口，限流阈值明明设了，峰值却一点没压下去：令牌桶补给完没有前移 last，令牌会被无限补；令牌数量没有按容量截断，突发流量可以攒出无限额度；限流键只取 IP，NAT 后的正常用户被一起限，攻击者换 IP 就绕过；IPv6 没有做规范化，同一个地址的不同写法被当成不同键；拒绝请求时仍然扣减令牌，正常用户被雪崩式误伤；扣减不是原子的，余额不足时扣了一半，计数漂移；时钟回拨时补出负令牌或直接补满，等于绕过限制；滑动窗口用固定窗口近似，窗口边界可以双倍放行；配置校验不检查容量与速率的量级关系，容量为零时永远拒绝；批量判定所有键共用一个状态，键之间互相耗尽额度。ratelimit/bucket.py 是核心，tests/test_bucket.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

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
