"""sec-rate-limit 的限流核心包。

对外暴露 :mod:`ratelimit.bucket` 中的 8 个契约函数；具体契约见各函数 docstring。
"""

from .bucket import (
    allow,
    consume,
    key_for,
    limit_batch,
    refill,
    sliding_window,
    token_bucket,
    validate_config,
)

__all__ = [
    "allow",
    "consume",
    "key_for",
    "limit_batch",
    "refill",
    "sliding_window",
    "token_bucket",
    "validate_config",
]

__version__ = "0.1.0"
