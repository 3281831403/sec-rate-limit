"""限流核心：令牌桶、限流键、原子扣减、滑动窗口与批量判定。

本模块只允许使用 Python 标准库（math、collections 等），不引入任何第三方依赖；
离线运行，不使用随机数；所有"当前时刻"都由调用方以整毫秒显式传入，
便于复现与并发边界判定。

通用约定
--------
- 时间：整毫秒（int），可用任意单调基准，不做时区换算。
- 令牌：float。比较使用绝对容差 ``1e-9``；任何函数的输出令牌数都不得为负。
- 限流器状态（``allow`` / ``consume`` 使用）::

      {"buckets": {key: {"tokens": float, "last": int}}}

  ``tokens`` 是当前余额，``last`` 是上一次补给/扣减发生的毫秒时刻。
  ``allow`` 必须**原地**更新该 dict（测试会直接读 ``state["buckets"]``），
  返回值只是布尔判定；``limit_batch`` 自己持有并返回状态。
- 安全前提：时钟可能回拨、IPv6 有多种写法、同一 IP 后面可能站着很多正常用户、
  批量请求之间可能互相偷令牌。任何"图省事"的近似都会变成绕过限流的入口。
"""

import ipaddress
import math

TOL = 1e-9

_STRATEGIES = ("ip", "user", "ip+route", "user+route")

# 匿名用户的内部标记：不可能出现在转义后的普通组件里（以 % 开头），
# 因此不会与任何字面量占位符（"-" / "None" / "null" / ...）碰撞。
_ANON = "%00anonymous"


def token_bucket(state, capacity, rate, now):
    """按经过的时间补给令牌，返回新的桶快照（不修改入参 state）。

    契约
    ----
    - ``elapsed = now - state["last"]``；若 ``elapsed < 0``（时钟回拨）按 0 处理，
      既不能补负令牌，也不能直接补满。
    - ``tokens = min(capacity, max(0.0, state["tokens"] + elapsed / 1000.0 * rate))``，
      即余额不足一个令牌也按小数保留，但绝不允许超过 ``capacity``。
    - 返回值的 ``"last"`` 必须是 ``max(state["last"], now)``：正常前进时等于 ``now``，
      回拨时保持原值，否则回拨一次就能把同一段时间反复兑换成令牌。
    - 纯函数：不得修改入参 ``state``。
    """
    last = state["last"]
    elapsed = now - last
    if elapsed < 0:
        elapsed = 0
    tokens = state["tokens"] + elapsed / 1000.0 * rate
    # 缺陷 2：按容量截断；同时保证不为负
    tokens = min(capacity, max(0.0, tokens))
    # 缺陷 1：last 前移（回拨时保持原值）
    return {"tokens": tokens, "last": max(last, now)}


def _escape_component(text):
    """转义组件中的 ``%``、``|`` 与控制字符（%XX 大写十六进制）。"""
    out = []
    for ch in text:
        code = ord(ch)
        if ch == "%" or ch == "|" or code < 0x20 or code == 0x7F:
            out.append("%{:02X}".format(code))
        else:
            out.append(ch)
    return "".join(out)


def _normalize_ip(ip):
    """IPv6 转规范压缩小写；IPv4 原样；无法解析则保留裁剪后的原文。"""
    ip = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        return addr.compressed  # 已是小写压缩形式
    return ip


def _normalize_route(route):
    """保证单 ``/`` 开头、合并重复 ``/``、去末尾 ``/``（根除外）、转小写。"""
    route = (route or "").strip().lower()
    if not route.startswith("/"):
        route = "/" + route
    while "//" in route:
        route = route.replace("//", "/")
    if len(route) > 1 and route.endswith("/"):
        route = route.rstrip("/")
        if not route:
            route = "/"
    return route


def _normalize_user(user):
    """缺省/None/空串 -> 匿名内部标记；其余去首尾空白、大小写敏感。"""
    if user is None:
        return _ANON
    user = str(user).strip()
    if not user:
        return _ANON
    return _escape_component(user)


def key_for(request, strategy):
    """把一次请求压成一个限流键，用于隔离不同主体/路由的额度。

    契约
    ----
    - ``ip``：去首尾空白；IPv6 必须转成规范压缩小写形式；IPv4 原样保留。
      无法解析的地址保留裁剪后的原文，不抛异常。
    - ``user``：去首尾空白，大小写敏感；缺省/None/空串一律视为匿名，且**不能**与
      字面量 ``"-"``、``"None"``、``"null"`` 等占位符共用同一个桶。
    - ``route``：去首尾空白；保证以单个 ``"/"`` 开头；合并重复的 ``"/"``；
      去掉末尾 ``"/"``（根 ``"/"`` 除外）；转小写。
    - 组件以 ``"|"`` 连接并带策略前缀；每个组件里的 ``"%"``、``"|"`` 以及所有控制字符
      必须先转义（``%`` -> ``%25``，``|`` -> ``%7C``，控制字符 -> ``%XX`` 大写十六进制）。
    - 策略为 ``"ip"`` 时只按 IP 聚合；``"ip+route"`` / ``"user+route"`` 必须把
      route（以及 user）纳入键；``"user+route"`` 还必须忽略 IP。
    """
    ip = _escape_component(_normalize_ip(request.get("ip")))
    user = _normalize_user(request.get("user"))
    route = _escape_component(_normalize_route(request.get("route")))

    if strategy == "ip":
        parts = [ip]
    elif strategy == "user":
        parts = [user]
    elif strategy == "ip+route":
        parts = [ip, route]
    elif strategy == "user+route":
        parts = [user, route]
    else:
        parts = [ip]
    return strategy + "|" + "|".join(parts)


def allow(state, request, config, now):
    """判定一次请求是否放行，并原地更新 state。

    契约
    ----
    - 先 ``key = key_for(request, config["strategy"])``。
    - 桶不存在时新建 ``{"tokens": float(capacity), "last": now}``（空桶从满额开始），
      已存在时先用 :func:`token_bucket` 补给并把新桶写回 ``state["buckets"][key]``。
    - 余额 ``>= 1.0`` 时扣掉 1 个令牌并返回 True；余额不足时返回 False 且**余额保持不变**。
    - 任何情况下 ``state["buckets"][key]["tokens"]`` 都不得为负。
    - 本函数不校验 config；需要校验时先调用 :func:`validate_config`。
    """
    key = key_for(request, config["strategy"])
    buckets = state["buckets"]
    capacity = float(config["capacity"])

    bucket = buckets.get(key)
    if bucket is None:
        bucket = {"tokens": capacity, "last": now}
    else:
        bucket = token_bucket(bucket, capacity, config["rate"], now)

    # 缺陷 5：拒绝时不扣令牌，余额保持不变
    if bucket["tokens"] >= 1.0 - TOL:
        bucket["tokens"] = max(0.0, bucket["tokens"] - 1.0)
        buckets[key] = bucket
        return True
    buckets[key] = bucket
    return False


def consume(state, key, n, now):
    """从某个键的桶里一次性扣掉 n 个令牌（全有或全无）。

    契约
    ----
    - 余额 ``>= n``：一次扣掉 n（不是逐个扣），``deducted == n``，``ok`` 为 True，
      ``tokens`` 为扣后余额，``state`` 中该桶的 ``last`` 更新为 ``now``。
    - 余额 ``< n``：**一个令牌都不扣**，``deducted == 0``，``ok`` 为 False，
      ``tokens`` / ``state`` 均保持原样。
    - ``key`` 不存在时抛 ``KeyError``；``n <= 0`` 时抛 ``ValueError``。
    - 浮点比较容差 ``1e-9``；扣减后余额不得为负。
    """
    if n <= 0:
        raise ValueError("n 必须为正整数")
    bucket = state["buckets"][key]  # 不存在时抛 KeyError

    tokens = bucket["tokens"]
    # 缺陷 6：全有或全无，余额不足时一个都不扣
    if tokens + TOL < n:
        return {"ok": False, "deducted": 0, "tokens": tokens}
    remaining = max(0.0, tokens - n)
    bucket["tokens"] = remaining
    bucket["last"] = now
    return {"ok": True, "deducted": n, "tokens": remaining}


def refill(clockskew_ms, rate):
    """时钟漂移/回拨时应当补给（或倒扣）的令牌量，返回 float。

    契约
    ----
    - ``clockskew_ms <= 0``（回拨或没有前进）必须返回 ``0.0``。
    - ``clockskew_ms > 0`` 时返回 ``clockskew_ms / 1000.0 * rate``，
      结果必须有限、非负（``math.isfinite``）。
    """
    if clockskew_ms <= 0:
        return 0.0
    amount = clockskew_ms / 1000.0 * rate
    if not math.isfinite(amount) or amount < 0.0:
        return 0.0
    return amount


def sliding_window(events, window_ms, now):
    """统计滑动窗口内的请求数，返回 int。

    契约
    ----
    - 区间左开右闭：``t == now - window_ms`` **不计入**，``t == now`` 计入，
      ``t > now`` 的未来时刻不计入。
    - 相同时刻的多个事件按条数计（不去重）。
    - 必须是真正的滑动窗口（逐事件比较），不得退化成固定窗口。
    - ``window_ms < 0`` 抛 ``ValueError``；``events`` 为空返回 0。
    """
    if window_ms < 0:
        raise ValueError("window_ms 不能为负")
    lower = now - window_ms
    count = 0
    for t in events:
        if lower < t <= now:
            count += 1
    return count


def validate_config(config):
    """检查限流配置，返回问题码列表；合法配置返回 ``[]``。

    问题码（按此顺序输出且不重复；缺字段或值为 None 视为非法，不抛异常）
    ------
    - ``"capacity_non_positive"``：``capacity <= 0``。
    - ``"capacity_below_unit"``：``0 < capacity < 1``。
    - ``"rate_non_positive"``：``rate <= 0``。
    - ``"rate_exceeds_capacity"``：``capacity > 0`` 且 ``rate > capacity``。
    - ``"window_negative"``：``window_ms < 0``。
    - ``"strategy_unknown"``：``strategy`` 不在已知策略集合内。
    """
    problems = []

    capacity = config.get("capacity")
    rate = config.get("rate")
    window_ms = config.get("window_ms")
    strategy = config.get("strategy")

    capacity_ok = isinstance(capacity, (int, float)) and not isinstance(capacity, bool)
    rate_ok = isinstance(rate, (int, float)) and not isinstance(rate, bool)

    # 缺陷 9：检查容量与速率的量级关系
    if not capacity_ok or capacity <= 0:
        problems.append("capacity_non_positive")
    elif capacity < 1:
        problems.append("capacity_below_unit")

    if not rate_ok or rate <= 0:
        problems.append("rate_non_positive")
    elif capacity_ok and capacity > 0 and rate > capacity:
        problems.append("rate_exceeds_capacity")

    if window_ms is not None and window_ms < 0:
        problems.append("window_negative")

    if strategy not in _STRATEGIES:
        problems.append("strategy_unknown")

    return problems


def limit_batch(requests, config):
    """批量判定：按时间顺序处理，每个键各自独立的桶。

    契约
    ----
    - 依次按 :func:`allow` 的规则判定，返回的 ``buckets`` 是本次批量结束后的
      限流器状态，可直接喂给后续的 :func:`allow` / :func:`consume`。
    - **每个键一个独立桶**：不同键之间不得共享 tokens / last。
    - 同一键的多个请求按时间先后消耗各自额度；时钟回拨的请求不得获得补给或补满。
    - 不修改入参 ``requests`` / ``config``；``requests`` 为空时返回空结果且计数为 0。
    - 本函数不校验 config；需要校验时先调用 :func:`validate_config`。
    """
    # 缺陷 10：每个键独立一个桶，各请求共用限流器 state 但桶按 key 隔离
    state = {"buckets": {}}
    decisions = []
    keys = []
    allowed = 0

    for item in requests:
        request = {"ip": item.get("ip"), "user": item.get("user"), "route": item.get("route")}
        key = key_for(request, config["strategy"])
        ok = allow(state, request, config, item["now"])
        keys.append(key)
        decisions.append(ok)
        if ok:
            allowed += 1

    return {
        "decisions": decisions,
        "keys": keys,
        "buckets": state["buckets"],
        "allowed": allowed,
        "rejected": len(requests) - allowed,
    }
