"""限流核心的行为契约测试（15 个，初始全红）。

每个用例只使用整毫秒时间戳、固定输入与 ``abs=1e-9`` 的浮点容差，
不联网、不随机、不依赖真实时钟。tests 目录不可修改。
"""

import pytest

from ratelimit.bucket import (
    allow,
    consume,
    key_for,
    limit_batch,
    refill,
    sliding_window,
    token_bucket,
    validate_config,
)

TOL = 1e-9


def _cfg(capacity=10.0, rate=1.0, window_ms=1000, strategy="ip"):
    return {
        "capacity": capacity,
        "rate": rate,
        "window_ms": window_ms,
        "strategy": strategy,
    }


def _req(ip="203.0.113.7", user=None, route="/api/login"):
    return {"ip": ip, "user": user, "route": route}


# ---------------------------------------------------------------- token_bucket


def test_token_bucket_refills_by_elapsed_and_advances_last():
    """缺陷 1：补给后必须把 last 前移到 now，否则同一毫秒会被反复兑换成令牌。"""
    bucket = {"tokens": 0.0, "last": 0}

    first = token_bucket(bucket, 10.0, 2.0, 1000)
    assert first["tokens"] == pytest.approx(2.0, abs=TOL)
    assert first["last"] == 1000

    # 同一时刻再算一次：上一次已经结算到 1000ms，不能又补 2 个
    again = token_bucket(first, 10.0, 2.0, 1000)
    assert again["tokens"] == pytest.approx(2.0, abs=TOL)
    assert again["last"] == 1000

    later = token_bucket(again, 10.0, 2.0, 1500)
    assert later["tokens"] == pytest.approx(3.0, abs=TOL)
    assert later["last"] == 1500

    # 纯函数：入参不被就地改写
    assert bucket == {"tokens": 0.0, "last": 0}


def test_token_bucket_clamps_tokens_to_capacity():
    """缺陷 2：空闲再久也只能攒到 capacity，突发不能被无限放大。"""
    bucket = {"tokens": 9.0, "last": 0}
    filled = token_bucket(bucket, 10.0, 100.0, 60_000)
    assert filled["tokens"] == pytest.approx(10.0, abs=TOL)
    assert filled["last"] == 60_000

    already_full = token_bucket({"tokens": 10.0, "last": 5}, 10.0, 100.0, 5)
    assert already_full["tokens"] == pytest.approx(10.0, abs=TOL)


def test_token_bucket_ignores_backwards_clock():
    """额外用例：时钟回拨不补令牌、也不把 last 倒着写回去。"""
    bucket = {"tokens": 3.0, "last": 10_000}

    rolled_back = token_bucket(bucket, 10.0, 1.0, 4_000)
    assert rolled_back["tokens"] == pytest.approx(3.0, abs=TOL)
    assert rolled_back["tokens"] >= 0.0
    assert rolled_back["last"] == 10_000

    # 回拨之后恢复正常时间线：只能从 last=10000 起算，不能被重复补一段
    recovered = token_bucket(rolled_back, 10.0, 1.0, 10_500)
    assert recovered["tokens"] == pytest.approx(3.5, abs=TOL)
    assert recovered["last"] == 10_500


# ---------------------------------------------------------------------- key_for


def test_key_for_separates_users_rotating_ips():
    """缺陷 3（含键碰撞）：按用户/路由隔离，换 IP 不能换出新额度。"""
    same_ip_a = key_for(_req(user="alice"), "user+route")
    same_ip_b = key_for(_req(user="bob"), "user+route")
    assert isinstance(same_ip_a, str) and same_ip_a
    assert same_ip_a != same_ip_b

    # 同一用户换 IP：仍然落在同一个键上，轮换 IP 绕不过限流
    other_ip = key_for(_req(ip="198.51.100.9", user="alice"), "user+route")
    assert other_ip == same_ip_a

    # ip+route 策略本来就按 IP 聚合：同一出口后的用户共享额度
    assert key_for(_req(user="alice"), "ip+route") == key_for(_req(user="bob"), "ip+route")

    # 路由规范化：大小写、重复斜杠、末尾斜杠都不该产生新桶
    assert key_for(_req(user="alice", route="/API//Login/"), "user+route") == same_ip_a

    # 缺失用户不能被字面量占位符顶替（键碰撞）
    anonymous = key_for(_req(user=None), "user+route")
    assert key_for(_req(user=""), "user+route") == anonymous
    for placeholder in ("-", "None", "null", "anonymous", "0"):
        assert key_for(_req(user=placeholder), "user+route") != anonymous

    # 组件里的分隔符与控制字符必须转义，不能拼出别人的键，也不能污染日志
    injected = key_for(_req(user="alice\nadmin|/api/login"), "user+route")
    assert injected != same_ip_a
    for bad in ("\n", "\r", "\x00", "\x1f"):
        assert bad not in injected


def test_key_for_canonicalizes_ipv6():
    """缺陷 4：IPv6 必须规范化，换写法不能刷新配额。"""
    compressed = key_for({"ip": "::1", "user": None, "route": "/x"}, "ip")
    expanded = key_for({"ip": "0:0:0:0:0:0:0:1", "user": None, "route": "/x"}, "ip")
    mixed = key_for({"ip": "  ::0:1  ", "user": None, "route": "/x"}, "ip")
    assert compressed == expanded == mixed

    long_form = key_for({"ip": "2001:DB8::1", "user": None, "route": "/x"}, "ip")
    long_form_expanded = key_for(
        {"ip": "2001:db8:0:0:0:0:0:1", "user": None, "route": "/x"}, "ip"
    )
    assert long_form == long_form_expanded

    assert compressed != key_for({"ip": "::2", "user": None, "route": "/x"}, "ip")
    assert key_for({"ip": "203.0.113.7 "}, "ip") == key_for({"ip": "203.0.113.7"}, "ip")


# ------------------------------------------------------------------------ allow


def test_empty_bucket_allows_first_request():
    """额外用例：容量 > 0 的新桶从满额开始，第一次请求必须放行。"""
    config = _cfg(capacity=2.0, rate=1.0)
    state = {"buckets": {}}

    assert allow(state, _req(), config, 0) is True

    key = next(iter(state["buckets"]))
    bucket = state["buckets"][key]
    assert bucket["tokens"] == pytest.approx(1.0, abs=TOL)
    assert bucket["last"] == 0


def test_capacity_boundary_allows_exactly_capacity():
    """额外用例（并发边界）：同一毫秒的请求只能放行 capacity 个，余额恰好归零。"""
    config = _cfg(capacity=3.0, rate=1.0)
    state = {"buckets": {}}
    request = _req(ip="198.51.100.1")

    results = [allow(state, request, config, 0) for _ in range(5)]
    assert results == [True, True, True, False, False]

    key = next(iter(state["buckets"]))
    tokens = state["buckets"][key]["tokens"]
    assert tokens == pytest.approx(0.0, abs=TOL)
    assert tokens >= 0.0

    # 恰好 1000ms 后补 1 个令牌：只够放行 1 次
    assert allow(state, request, config, 1000) is True
    assert allow(state, request, config, 1000) is False
    assert state["buckets"][key]["tokens"] == pytest.approx(0.0, abs=TOL)


def test_different_keys_do_not_share_tokens():
    """额外用例：不同键互不影响，一个键被打空不能拖累另一个键。"""
    config = _cfg(capacity=1.0, rate=1.0)
    state = {"buckets": {}}

    assert allow(state, _req(ip="10.1.1.1"), config, 0) is True
    assert allow(state, _req(ip="10.1.1.2"), config, 0) is True
    assert allow(state, _req(ip="10.1.1.1"), config, 0) is False
    assert len(state["buckets"]) == 2


def test_allow_keeps_balance_when_rejecting():
    """缺陷 5：拒绝时不得扣令牌，余额不能被"惩罚性扣减"打成负数。"""
    config = _cfg(capacity=1.0, rate=1.0)
    state = {"buckets": {}}
    request = _req()

    assert allow(state, request, config, 0) is True
    key = next(iter(state["buckets"]))
    assert state["buckets"][key]["tokens"] == pytest.approx(0.0, abs=TOL)

    state["buckets"][key]["tokens"] = 0.5
    assert allow(state, request, config, 0) is False
    assert state["buckets"][key]["tokens"] == pytest.approx(0.5, abs=TOL)

    # 攒够 1 个令牌后恢复放行，且结算干净
    assert allow(state, request, config, 1000) is True
    assert state["buckets"][key]["tokens"] == pytest.approx(0.0, abs=TOL)

    # 已经归零时再被拒，也不能出现负余额
    assert allow(state, request, config, 1000) is False
    assert state["buckets"][key]["tokens"] == pytest.approx(0.0, abs=TOL)
    assert state["buckets"][key]["tokens"] >= 0.0


# ---------------------------------------------------------------------- consume


def test_consume_is_all_or_nothing():
    """缺陷 6：余额不足时一个令牌都不扣，避免计数漂移。"""
    state = {"buckets": {"k": {"tokens": 2.0, "last": 0}}}

    rejected = consume(state, "k", 5, 100)
    assert rejected["ok"] is False
    assert rejected["deducted"] == 0
    assert rejected["tokens"] == pytest.approx(2.0, abs=TOL)
    assert state["buckets"]["k"]["tokens"] == pytest.approx(2.0, abs=TOL)
    assert state["buckets"]["k"]["last"] == 0

    accepted = consume(state, "k", 2, 100)
    assert accepted["ok"] is True
    assert accepted["deducted"] == 2
    assert accepted["tokens"] == pytest.approx(0.0, abs=TOL)
    assert state["buckets"]["k"]["tokens"] == pytest.approx(0.0, abs=TOL)
    assert state["buckets"]["k"]["last"] == 100
    assert state["buckets"]["k"]["tokens"] >= 0.0

    empty = consume(state, "k", 1, 100)
    assert empty["ok"] is False
    assert empty["deducted"] == 0
    assert empty["tokens"] == pytest.approx(0.0, abs=TOL)

    with pytest.raises(KeyError):
        consume(state, "missing", 1, 100)
    with pytest.raises(ValueError):
        consume(state, "k", 0, 100)


# ----------------------------------------------------------------------- refill


def test_refill_credits_nothing_on_clock_rollback():
    """缺陷 7：回拨既不能补负令牌，也不能直接补满。"""
    assert refill(0, 5.0) == pytest.approx(0.0, abs=TOL)
    assert refill(-1, 1_000_000.0) == pytest.approx(0.0, abs=TOL)
    assert refill(-1000, 5.0) == pytest.approx(0.0, abs=TOL)
    assert refill(2000, 0.5) == pytest.approx(1.0, abs=TOL)
    assert refill(500, 4.0) == pytest.approx(2.0, abs=TOL)


# --------------------------------------------------------------- sliding_window


def test_sliding_window_uses_true_lookback():
    """缺陷 8：真滑动窗口，不能退化成固定窗口让边界两侧各放行一批。"""
    events = [0, 1, 500, 999, 1000, 1001, 2000]

    # (0, 1000] -> 1, 500, 999, 1000
    assert sliding_window(events, 1000, 1000) == 4
    # now - window 是开区间端点：999 不计入，1000 计入
    assert sliding_window([999, 1000], 1000, 1999) == 1
    # 未来时刻不计入
    assert sliding_window([1000, 1001, 1500], 1000, 1000) == 1
    # 相同时刻按条数计
    assert sliding_window([1000, 1000, 1000], 1000, 1000) == 3
    assert sliding_window([], 1000, 0) == 0
    assert sliding_window([7], 0, 7) == 0

    with pytest.raises(ValueError):
        sliding_window([1], -1, 0)


# ------------------------------------------------------------- validate_config


def test_validate_config_rejects_always_denying_settings():
    """缺陷 9：必须检查容量/速率的量级关系，永久拒绝的配置不能被放行。"""
    assert validate_config(_cfg()) == []

    assert validate_config(
        {"capacity": 0.5, "rate": 0.0, "window_ms": -1, "strategy": "ip"}
    ) == ["capacity_below_unit", "rate_non_positive", "window_negative"]

    assert validate_config(
        {"capacity": 0.0, "rate": 1.0, "window_ms": 1000, "strategy": "ip"}
    ) == ["capacity_non_positive"]

    assert validate_config(
        {"capacity": 10.0, "rate": 50.0, "window_ms": 1000, "strategy": "ip"}
    ) == ["rate_exceeds_capacity"]

    assert validate_config(
        {"capacity": 10.0, "rate": 1.0, "window_ms": 1000, "strategy": "cookie"}
    ) == ["strategy_unknown"]

    assert validate_config({}) == [
        "capacity_non_positive",
        "rate_non_positive",
        "strategy_unknown",
    ]


# ------------------------------------------------------------------ limit_batch


def test_limit_batch_isolates_buckets_per_key():
    """缺陷 10：每个键独立一个桶，不能所有键共用一个 state 互相耗尽。"""
    config = _cfg(capacity=1.0, rate=1.0, strategy="ip")
    requests = [
        {"ip": "10.0.0.1", "user": None, "route": "/login", "now": 0},
        {"ip": "10.0.0.2", "user": None, "route": "/login", "now": 0},
        {"ip": "10.0.0.1", "user": None, "route": "/login", "now": 10},
    ]

    result = limit_batch(requests, config)
    assert result["decisions"] == [True, True, False]
    assert result["allowed"] == 2
    assert result["rejected"] == 1
    assert len(result["buckets"]) == 2
    assert result["keys"] == [
        key_for({"ip": "10.0.0.1", "user": None, "route": "/login"}, "ip"),
        key_for({"ip": "10.0.0.2", "user": None, "route": "/login"}, "ip"),
        key_for({"ip": "10.0.0.1", "user": None, "route": "/login"}, "ip"),
    ]

    # 入参不被改写
    assert requests[0]["now"] == 0
    assert config["capacity"] == 1.0


def test_batch_decisions_match_individual_allow_calls():
    """额外用例：两请求独立判定与逐条单独 allow 的结果必须一致。"""
    config = _cfg(capacity=2.0, rate=1.0, strategy="user+route")
    requests = [
        {"ip": "10.0.0.1", "user": "u1", "route": "/x", "now": 0},
        {"ip": "10.0.0.2", "user": "u1", "route": "/x", "now": 5},
        {"ip": "10.0.0.1", "user": "u2", "route": "/x", "now": 7},
        {"ip": "10.0.0.1", "user": "u1", "route": "/x", "now": 8},
    ]

    batch = limit_batch(requests, config)
    state = {"buckets": {}}
    individually = [
        allow(
            state,
            {"ip": item["ip"], "user": item["user"], "route": item["route"]},
            config,
            item["now"],
        )
        for item in requests
    ]

    assert batch["decisions"] == individually == [True, True, True, False]
    assert batch["allowed"] == 3 and batch["rejected"] == 1

    # 前两个请求同一用户同一路由、IP 不同 -> 必须同键；第三个换用户 -> 必须不同键
    keys = batch["keys"]
    assert keys[0] == keys[1] != keys[2]
    assert keys[0] == key_for({"ip": "10.0.0.1", "user": "u1", "route": "/x"}, "user+route")
