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


def token_bucket(state, capacity, rate, now):
    """按经过的时间补给令牌，返回新的桶快照（不修改入参 state）。

    参数
    ----
    state : dict
        单个桶，形如 ``{"tokens": float, "last": int}``；``last`` 是上次补给时刻(ms)。
        注意这里**不是**整个限流器状态。
    capacity : float
        桶容量，令牌总数上限（> 0）。
    rate : float
        补给速率，单位"令牌/秒"（>= 0）。
    now : int
        当前时刻（整毫秒）。

    返回
    ----
    dict
        新桶 ``{"tokens": float, "last": int}``。

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
    raise NotImplementedError("token_bucket 尚未实现，契约见 docstring")


def key_for(request, strategy):
    """把一次请求压成一个限流键，用于隔离不同主体/路由的额度。

    参数
    ----
    request : dict
        ``{"ip": str, "user": str | None, "route": str}``；``user`` 可缺省或为 None。
    strategy : str
        组合策略，取值 ``"ip"`` | ``"user"`` | ``"ip+route"`` | ``"user+route"``。

    返回
    ----
    str
        非空键。

    契约
    ----
    - ``ip``：去首尾空白；IPv6 必须转成规范压缩小写形式，使 ``0:0:0:0:0:0:0:1``、
      ``::1``、``2001:DB8::1``、``2001:db8:0:0:0:0:0:1`` 各自等价；IPv4 原样保留。
      无法解析的地址保留裁剪后的原文，不抛异常。
    - ``user``：去首尾空白，大小写敏感；缺省/None/空串一律视为匿名，且**不能**与
      字面量 ``"-"``、``"None"``、``"null"`` 等占位符共用同一个桶。
    - ``route``：去首尾空白；保证以单个 ``"/"`` 开头；合并重复的 ``"/"``；
      去掉末尾 ``"/"``（根 ``"/"`` 除外）；转小写。
    - 组件以 ``"|"`` 连接并带策略前缀；每个组件里的 ``"%"``、``"|"`` 以及所有控制字符
      必须先转义（``%`` -> ``%25``，``|`` -> ``%7C``，控制字符 -> ``%XX`` 大写十六进制），
      否则请求里的一个 ``"|"`` 就能伪造出别人的键（键碰撞），返回的键中不得含有换行、
      回车、NUL 等控制字符。
    - 策略为 ``"ip"`` 时只按 IP 聚合（NAT 出口共用额度是这类策略的已知取舍）；
      ``"ip+route"`` / ``"user+route"`` 必须把 route（以及 user）纳入键，使同一 IP 后的
      不同用户彼此独立；``"user+route"`` 还必须忽略 IP，避免攻击者轮换 IP 拿到新额度。
    """
    raise NotImplementedError("key_for 尚未实现，契约见 docstring")


def allow(state, request, config, now):
    """判定一次请求是否放行，并原地更新 state。

    参数
    ----
    state : dict
        ``{"buckets": {key: {"tokens": float, "last": int}}}``；首次见到的键要新建桶。
    request : dict
        见 :func:`key_for`。
    config : dict
        ``{"capacity": float, "rate": float, "window_ms": int, "strategy": str}``。
    now : int
        当前时刻（整毫秒）。

    返回
    ----
    bool
        放行 True / 拒绝 False。

    契约
    ----
    - 先 ``key = key_for(request, config["strategy"])``。
    - 桶不存在时新建 ``{"tokens": float(capacity), "last": now}``（空桶从满额开始），
      已存在时先用 :func:`token_bucket` 补给并把新桶写回 ``state["buckets"][key]``。
    - 余额 ``>= 1.0`` 时扣掉 1 个令牌并返回 True；余额不足时返回 False 且**余额保持不变**
      （不得为了"惩罚"拒绝请求而扣令牌，否则被打的键余额变负，合法用户被长时间拒绝）。
    - 任何情况下 ``state["buckets"][key]["tokens"]`` 都不得为负。
    - 本函数不校验 config；需要校验时先调用 :func:`validate_config`。
    """
    raise NotImplementedError("allow 尚未实现，契约见 docstring")


def consume(state, key, n, now):
    """从某个键的桶里一次性扣掉 n 个令牌（全有或全无）。

    参数
    ----
    state : dict
        限流器状态 ``{"buckets": {key: {"tokens": float, "last": int}}}``。
    key : str
        已经存在的限流键（本函数不创建、也不补给令牌）。
    n : int
        本次要扣的令牌数（> 0）。
    now : int
        当前时刻（整毫秒），扣减成功时写回桶的 ``last``。

    返回
    ----
    dict
        ``{"ok": bool, "deducted": int, "tokens": float}``。

    契约
    ----
    - 余额 ``>= n``：一次扣掉 n（不是逐个扣），``deducted == n``，``ok`` 为 True，
      ``tokens`` 为扣后余额，``state`` 中该桶的 ``last`` 更新为 ``now``。
    - 余额 ``< n``：**一个令牌都不扣**，``deducted == 0``，``ok`` 为 False，
      ``tokens`` / ``state`` 均保持原样（不允许扣掉一部分造成计数漂移）。
    - ``key`` 不存在时抛 ``KeyError``；``n <= 0`` 时抛 ``ValueError``。
    - 浮点比较容差 ``1e-9``；扣减后余额不得为负。
    """
    raise NotImplementedError("consume 尚未实现，契约见 docstring")


def refill(clockskew_ms, rate):
    """时钟漂移/回拨时应当补给（或倒扣）的令牌量，返回 float。

    参数
    ----
    clockskew_ms : int
        本机时钟相对基准的前进量(ms)，可以为负（回拨）或 0。
    rate : float
        补给速率（令牌/秒）。

    返回
    ----
    float
        应补给的令牌增量。

    契约
    ----
    - ``clockskew_ms <= 0``（回拨或没有前进）必须返回 ``0.0``：
      既不能返回负数（余额被扣成负数，等于攻击者改时钟还能"省费"），
      也不能返回"补满"（等于直接绕过限流）。
    - ``clockskew_ms > 0`` 时返回 ``clockskew_ms / 1000.0 * rate``，
      结果必须有限、非负（``math.isfinite``）。
    """
    raise NotImplementedError("refill 尚未实现，契约见 docstring")


def sliding_window(events, window_ms, now):
    """统计滑动窗口内的请求数，返回 int。

    参数
    ----
    events : list[int]
        已发生请求的时刻序列（整毫秒；可乱序、可含重复、可含未来时刻）。
    window_ms : int
        窗口长度(ms)，``>= 0``。
    now : int
        当前时刻（整毫秒）。

    返回
    ----
    int
        落在 ``(now - window_ms, now]`` 内的请求数。

    契约
    ----
    - 区间左开右闭：``t == now - window_ms`` **不计入**，``t == now`` 计入，
      ``t > now`` 的未来时刻不计入。
    - 相同时刻的多个事件按条数计（不去重）。
    - 必须是真正的滑动窗口（逐事件比较），不得退化成按 ``now // window_ms``
      切分的固定窗口：固定窗口在边界两侧各放行一批，峰值会翻倍。
    - ``window_ms < 0`` 抛 ``ValueError``；``events`` 为空返回 0。
    """
    raise NotImplementedError("sliding_window 尚未实现，契约见 docstring")


def validate_config(config):
    """检查限流配置，返回问题码列表；合法配置返回 ``[]``。

    参数
    ----
    config : dict
        ``{"capacity": float, "rate": float, "window_ms": int, "strategy": str}``。

    返回
    ----
    list[str]
        问题码列表，按下面顺序输出且不重复；缺字段或值为 None 视为非法，
        但本函数**不抛异常**，只把问题码放进列表。

    问题码
    ------
    - ``"capacity_non_positive"``：``capacity <= 0``，桶永远空，全部请求被拒。
    - ``"capacity_below_unit"``：``0 < capacity < 1``，一次请求要 1 个令牌，
      桶永远凑不齐，同样是永久拒绝（量级关系必须检查，不能只看 <= 0）。
    - ``"rate_non_positive"``：``rate <= 0``，桶耗空后再也补不回来。
    - ``"rate_exceeds_capacity"``：``capacity > 0`` 且 ``rate > capacity``，
      不足 1 秒就能补满整桶，限流形同虚设（容量与速率的量级关系）。
    - ``"window_negative"``：``window_ms < 0``。
    - ``"strategy_unknown"``：``strategy`` 不在
      ``{"ip", "user", "ip+route", "user+route"}`` 内。
    """
    raise NotImplementedError("validate_config 尚未实现，契约见 docstring")


def limit_batch(requests, config):
    """批量判定：按时间顺序处理，每个键各自独立的桶。

    参数
    ----
    requests : list[dict]
        ``[{"ip": str, "user": str | None, "route": str, "now": int}, ...]``，
        按 ``now`` 非递减排列（相同 now 保持原顺序）。
    config : dict
        同 :func:`allow`。

    返回
    ----
    dict
        ``{"decisions": list[bool], "keys": list[str], "buckets": dict,
        "allowed": int, "rejected": int}``；``decisions`` / ``keys`` 与入参顺序一一对应。

    契约
    ----
    - 依次按 :func:`allow` 的规则判定，返回的 ``buckets`` 是本次批量结束后的
      限流器状态，可直接喂给后续的 :func:`allow` / :func:`consume`。
    - **每个键一个独立桶**：不同键之间不得共享 tokens / last，也不得因为
      某个键被耗尽而影响其它键（不能把同一份 state 复用给所有键）。
    - 同一键的多个请求按时间先后消耗各自额度；时钟回拨的请求不得获得补给或补满。
    - 不修改入参 ``requests`` / ``config``；``requests`` 为空时返回空结果且计数为 0。
    - 本函数不校验 config；需要校验时先调用 :func:`validate_config`。
    """
    raise NotImplementedError("limit_batch 尚未实现，契约见 docstring")
